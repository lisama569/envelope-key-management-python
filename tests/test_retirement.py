"""密钥版本退役：退役后解密以可区分原因被拒；还有未迁完数据时拒绝退役。"""

import logging

import pytest

from app.authz import Caller
from app.errors import (
    AuthorizationError,
    KeyNotFoundError,
    KeyScopeError,
    KeyVersionRetiredError,
    RetirementBlockedError,
)
from app.models import KeyStatus, MigrationStatus
from app.service import KeyManagementService

logger = logging.getLogger("kms.test")


@pytest.fixture()
def migrated_setup(svc):
    """v1 老密文 -> 轮换 v2 -> 全部迁移完成。返回 (旧信封, 迁移后信封)。"""
    old = svc.encrypt("app-orders", "orders", b"to-be-migrated", aad=b"c")
    svc.rotate_key("admin", "orders")
    result = svc.migrate_batch("app-orders", [old])
    new_env = result.items[0].envelope
    return old, new_env


def test_retire_archived_version_succeeds_after_migration(svc, migrated_setup):
    old, new_env = migrated_setup
    svc.retire_version("admin", "orders", 1)
    kv = svc.keystore.get_version("orders", 1)
    assert kv.status is KeyStatus.RETIRED
    logger.info("判定依据: 无未迁项, v1 ARCHIVED -> RETIRED")


def test_decrypt_retired_version_rejected_with_distinct_code(svc, migrated_setup):
    old, new_env = migrated_setup
    svc.retire_version("admin", "orders", 1)

    # 退役版本解密：专门的 code，与"不存在"和"越权"都不同
    with pytest.raises(KeyVersionRetiredError) as exc:
        svc.decrypt("app-orders", old, aad=b"c")
    assert exc.value.code == "key_version_retired"
    logger.info("判定依据: 已退役版本解密 -> %s (区别于 key_not_found/授权错误)",
                exc.value.code)

    # 明确三者互不相同，可被分别捕获
    assert KeyVersionRetiredError is not KeyNotFoundError
    assert KeyVersionRetiredError is not AuthorizationError
    assert KeyVersionRetiredError is not KeyScopeError


def test_decrypt_nonexistent_version_still_key_not_found(svc, migrated_setup):
    old, _ = migrated_setup
    svc.retire_version("admin", "orders", 1)
    forged = type(old)(key_id=old.key_id, key_version=99, iv=old.iv,
                       ciphertext=old.ciphertext, tag=old.tag, aad=old.aad)
    with pytest.raises(KeyNotFoundError) as exc:
        svc.decrypt("app-orders", forged)
    assert exc.value.code == "key_not_found"
    logger.info("判定依据: 根本不存在的版本仍是 %s, 未与退役混淆", exc.value.code)


def test_migrated_data_unaffected_after_retirement(svc, migrated_setup):
    old, new_env = migrated_setup
    svc.retire_version("admin", "orders", 1)
    # 退役前已经迁到 v2 的历史数据照样能解
    assert svc.decrypt("app-orders", new_env, aad=b"c") == b"to-be-migrated"
    logger.info("判定依据: 退役后 v2 上的已迁数据解密正常, 老数据兼容")


def test_retire_blocked_while_ciphertext_not_migrated(svc):
    old = svc.encrypt("app-orders", "orders", b"never-migrated")
    svc.rotate_key("admin", "orders")
    # 没有提交过迁移：把关不掌握该密文，这里通过显式提交后失败来验证"还有未迁完"
    # 更直接的场景：迁移项仍 FAILED/PENDING
    from app.migration import envelope_fingerprint
    fp = envelope_fingerprint(old)
    svc.migrations.begin(fp, "orders", 1)  # PENDING/PROCESSING 残留

    with pytest.raises(RetirementBlockedError) as exc:
        svc.retire_version("admin", "orders", 1)
    assert exc.value.code == "retirement_blocked"
    assert svc.keystore.get_version("orders", 1).status is KeyStatus.ARCHIVED
    logger.info("判定依据: v1 仍有未迁完密文 -> %s, 状态保持 ARCHIVED", exc.value.code)


def test_retire_blocked_when_last_batch_has_failure(svc):
    """上一次迁移还有没成功的项（瞬时故障）时拒绝退役；重试成功后放行。"""
    from app.crypto import EnvelopeCipher
    from app.errors import IntegrityError

    old = svc.encrypt("app-orders", "orders", b"retry-me")
    svc.rotate_key("admin", "orders")
    real_cipher = svc._cipher

    class FlakyCipher(EnvelopeCipher):
        def __init__(self):
            self.failing = True

        def decrypt(self, key, envelope, aad=b""):
            if self.failing:
                self.failing = False  # 仅失败一次，重试即恢复
                raise IntegrityError("simulated transient failure")
            return real_cipher.decrypt(key, envelope, aad)

        def encrypt(self, key, plaintext, aad=b""):
            return real_cipher.encrypt(key, plaintext, aad)

    flaky = FlakyCipher()
    svc._cipher = flaky

    first = svc.migrate_batch("app-orders", [old])
    assert first.items[0].status is MigrationStatus.FAILED

    with pytest.raises(RetirementBlockedError) as exc:
        svc.retire_version("admin", "orders", 1)
    assert exc.value.code == "retirement_blocked"
    logger.info("判定依据: 上次迁移有未成功项 -> %s", exc.value.code)

    # 故障恢复后重试同一项，成功；再退役即放行
    svc._cipher = real_cipher
    again = svc.migrate_batch("app-orders", [old])
    assert again.items[0].status is MigrationStatus.MIGRATED
    svc.retire_version("admin", "orders", 1)
    assert svc.keystore.get_version("orders", 1).status is KeyStatus.RETIRED
    logger.info("判定依据: 重试成功、无未完成项后把关放行, v1 RETIRED")


def test_cannot_retire_active_version(svc):
    with pytest.raises(RetirementBlockedError) as exc:
        svc.retire_version("admin", "orders", 1)
    assert exc.value.code == "retirement_blocked"
    assert svc.keystore.get_version("orders", 1).status is KeyStatus.ACTIVE
    logger.info("判定依据: ACTIVE 版本须先轮换再退役")


def test_retire_unknown_version_is_not_found(svc):
    with pytest.raises(KeyNotFoundError):
        svc.retire_version("admin", "orders", 99)
    logger.info("判定依据: 不存在的版本退役 -> key_not_found")


def test_retire_is_idempotent(svc, migrated_setup):
    _, _ = migrated_setup
    svc.retire_version("admin", "orders", 1)
    svc.retire_version("admin", "orders", 1)  # 重复退役不报错
    retires = [r for r in svc.audit.records() if r.action == "retire_key"]
    assert len(retires) == 1, "幂等退役不重复写审计"
    logger.info("判定依据: 重复退役幂等成功, 审计只记一条")


def test_retire_requires_permission(svc, migrated_setup):
    with pytest.raises(AuthorizationError):
        svc.retire_version("app-orders", "orders", 1)
    logger.info("判定依据: 无 rotate 权限的调用方不得退役")


def test_retire_persists_across_restart(tmp_path):
    state_dir = str(tmp_path / "state")
    svc = KeyManagementService(state_dir=state_dir)
    svc.authorizer.register(Caller(
        name="admin", allowed_key_ids=frozenset({"orders"}),
        can_rotate=True, can_create=True))
    svc.authorizer.register(Caller(name="app-orders", allowed_key_ids=frozenset({"orders"})))
    svc.create_key("admin", "orders")
    old = svc.encrypt("app-orders", "orders", b"persist")
    svc.rotate_key("admin", "orders")
    new_env = svc.migrate_batch("app-orders", [old]).items[0].envelope
    svc.retire_version("admin", "orders", 1)

    svc2 = KeyManagementService(state_dir=state_dir)
    assert svc2.keystore.get_version("orders", 1).status is KeyStatus.RETIRED
    with pytest.raises(KeyVersionRetiredError):
        svc2.decrypt("app-orders", old)
    assert svc2.decrypt("app-orders", new_env) == b"persist"
    assert svc2.audit.verify()
    logger.info("判定依据: 重启后退役状态与已迁数据可用性均保持")
