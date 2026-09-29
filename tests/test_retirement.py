"""密钥版本退役：可区分的拒绝原因、迁移把关、退役后已迁数据不受影响。"""

import logging

import pytest

from app.authz import Caller
from app.crypto import EnvelopeCipher
from app.errors import (
    AuthorizationError,
    IntegrityError,
    KeyNotFoundError,
    KeyRetiredError,
    RetirementBlockedError,
)
from app.models import KeyStatus

logger = logging.getLogger("kms.test")


class FailOnceCipher(EnvelopeCipher):
    """对指定密文制造一次性解密失败。"""

    def __init__(self) -> None:
        self.failing: set[bytes] = set()

    def fail_once(self, marker: bytes) -> None:
        self.failing.add(marker)

    def decrypt(self, key, envelope, aad: bytes = b""):
        if envelope.ciphertext in self.failing:
            self.failing.discard(envelope.ciphertext)
            raise IntegrityError("transient failure")
        return super().decrypt(key, envelope, aad)


@pytest.fixture()
def svc_failonce():
    from app.authz import Caller
    from app.service import KeyManagementService

    cipher = FailOnceCipher()
    service = KeyManagementService(cipher=cipher)
    service.authorizer.register(Caller(
        name="admin", allowed_key_ids=frozenset({"orders", "payments"}),
        can_rotate=True, can_create=True,
    ))
    service.authorizer.register(Caller(name="app-orders", allowed_key_ids=frozenset({"orders"})))
    service.create_key("admin", "orders")
    return service, cipher


def test_retire_requires_permission(svc):
    svc.rotate_key("admin", "orders")
    with pytest.raises(AuthorizationError) as exc_info:
        svc.retire_key("app-orders", "orders", 1)  # 无 rotate/retire 权限
    logger.info("判定依据: 无退役权限 -> %s", exc_info.value.code)
    assert exc_info.value.code == "authorization_error"


def test_retire_unknown_version_is_not_retired_error(svc):
    svc.rotate_key("admin", "orders")
    with pytest.raises(KeyNotFoundError) as exc_info:
        svc.retire_key("admin", "orders", 99)
    logger.info("判定依据: 退役不存在的版本 -> key_not_found（区别于 key_retired）")
    assert exc_info.value.code == "key_not_found"


def test_cannot_retire_active_version(svc):
    with pytest.raises(RetirementBlockedError):
        svc.retire_key("admin", "orders", 1)
    assert svc.keystore.get_version("orders", 1).status is KeyStatus.ACTIVE
    logger.info("判定依据: ACTIVE 版本不可退役，状态未被改动")


def test_retirement_blocked_while_migration_incomplete(svc_failonce):
    svc, cipher = svc_failonce
    e1 = svc.encrypt("app-orders", "orders", b"one")
    e2 = svc.encrypt("app-orders", "orders", b"two")
    cipher.fail_once(e2.ciphertext)
    svc.rotate_key("admin", "orders")

    report = svc.migrate_batch("app-orders", "orders", [e1, e2], batch_id="B")
    assert len(report.failed) == 1

    with pytest.raises(RetirementBlockedError) as exc_info:
        svc.retire_key("admin", "orders", 1)
    message = str(exc_info.value)
    logger.info("退役被拒原因: code=%s message=%s", exc_info.value.code, message)
    assert exc_info.value.code == "retirement_blocked"
    assert "1 ciphertext item(s)" in message
    assert "B" in message  # 点得到是哪个批次的哪一项

    # 全部迁完后把关放行
    svc.migrate_batch("app-orders", "orders", [e1, e2], batch_id="B")
    assert svc.retire_key("admin", "orders", 1) == 1
    assert svc.keystore.get_version("orders", 1).status is KeyStatus.RETIRED
    logger.info("判定依据: 未成功项清零后退役成功, 版本状态=retired")


def test_decrypt_retired_version_rejected_with_distinct_code(svc):
    old = svc.encrypt("app-orders", "orders", b"old")
    svc.rotate_key("admin", "orders")
    report = svc.migrate_batch("app-orders", "orders", [old], batch_id="B")
    svc.retire_key("admin", "orders", 1)

    with pytest.raises(KeyRetiredError) as exc_info:
        svc.decrypt("app-orders", old)
    assert exc_info.value.code == "key_retired"
    logger.info("判定依据: 退役版本解密 -> code=key_retired（区别于 key_not_found/越权）")


def test_retired_distinct_from_not_found_and_authz(svc):
    from dataclasses import replace

    old = svc.encrypt("app-orders", "orders", b"old")
    svc.rotate_key("admin", "orders")
    svc.migrate_batch("app-orders", "orders", [old], batch_id="B")
    svc.retire_key("admin", "orders", 1)

    # 退役但存在 -> key_retired
    with pytest.raises(KeyRetiredError) as exc:
        svc.decrypt("app-orders", old)
    code_retired = exc.value.code

    # 版本根本不存在 -> key_not_found
    with pytest.raises(KeyNotFoundError) as exc:
        svc.decrypt("app-orders", replace(old, key_version=42))
    code_missing = exc.value.code

    # 越权 -> key_scope_error（授权检查先于状态检查）
    svc.authorizer.register(Caller(
        name="outsider", allowed_key_ids=frozenset({"payments"})))
    with pytest.raises(Exception) as exc:
        svc.decrypt("outsider", old)
    code_scope = exc.value.code

    logger.info("判定依据: 三种拒绝原因各自独立: %s / %s / %s",
                code_retired, code_missing, code_scope)
    assert len({code_retired, code_missing, code_scope}) == 3
    assert (code_retired, code_missing, code_scope) == (
        "key_retired", "key_not_found", "key_scope_error")


def test_migrated_data_still_decrypts_after_retirement(svc):
    old = svc.encrypt("app-orders", "orders", b"history", aad=b"tenant")
    svc.rotate_key("admin", "orders")
    report = svc.migrate_batch("app-orders", "orders", [old], batch_id="B")
    migrated = report.migrated[0].envelope
    assert svc.decrypt("app-orders", migrated, aad=b"tenant") == b"history"

    svc.retire_key("admin", "orders", 1)
    # 退役前已迁过去的数据不受影响
    assert svc.decrypt("app-orders", migrated, aad=b"tenant") == b"history"
    # 新版本继续加密、解密
    new_env = svc.encrypt("app-orders", "orders", b"after-retire")
    assert svc.decrypt("app-orders", new_env) == b"after-retire"
    logger.info("判定依据: v1 退役后, 迁到 v2 的历史密文与新加密均正常解密")


def test_retire_is_idempotent_and_audited(svc):
    old = svc.encrypt("app-orders", "orders", b"old")
    svc.rotate_key("admin", "orders")
    svc.migrate_batch("app-orders", "orders", [old], batch_id="B")
    assert svc.retire_key("admin", "orders", 1) == 1
    assert svc.retire_key("admin", "orders", 1) == 1  # 幂等
    records = [r for r in svc.audit.records() if r.action == "retire_key"]
    assert len(records) == 1, "重复退役不重复写审计"
    assert svc.audit.verify()
    logger.info("判定依据: 重复退役幂等返回, 仅一条 retire_key 审计, 哈希链有效")
