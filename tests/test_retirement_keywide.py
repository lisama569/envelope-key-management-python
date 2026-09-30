"""退役把关（整把密钥维度）：别的版本还有失败/未迁项时同样拦截，全部迁完才放行。"""

import logging
import threading
from dataclasses import replace

import pytest

from app.authz import Caller
from app.crypto import EnvelopeCipher
from app.errors import IntegrityError, KeyRetiredError, RetirementBlockedError
from app.models import KeyStatus
from app.service import KeyManagementService

logger = logging.getLogger("kms.test")


class FailOnceCipher(EnvelopeCipher):
    """对指定密文制造一次性解密失败（模拟迁移卡在 FAILED）。"""

    def __init__(self) -> None:
        self.failing: set[bytes] = set()

    def fail_once(self, marker: bytes) -> None:
        self.failing.add(marker)

    def decrypt(self, key, envelope, aad: bytes = b""):
        if envelope.ciphertext in self.failing:
            self.failing.discard(envelope.ciphertext)
            raise IntegrityError("transient failure")
        return super().decrypt(key, envelope, aad)


def _service(cipher=None):
    svc = KeyManagementService(cipher=cipher)
    svc.authorizer.register(Caller(
        name="admin", allowed_key_ids=frozenset({"orders"}),
        can_rotate=True, can_create=True,
    ))
    svc.authorizer.register(Caller(name="app", allowed_key_ids=frozenset({"orders"})))
    svc.create_key("admin", "orders")
    return svc


def test_retire_blocked_by_failed_item_on_other_version():
    """v2 名下批次还有 FAILED 项时，v1（自己名下项都已迁完）也必须被拦住。"""
    cipher = FailOnceCipher()
    svc = _service(cipher)

    # v1 老密文（batch-A）；轮换出 v2，batch-A 全部迁完 v1->v2
    v1_envs = [svc.encrypt("app", "orders", b"v1-a"),
               svc.encrypt("app", "orders", b"v1-b")]
    svc.rotate_key("admin", "orders")  # active=v2, v1 archived
    r_a = svc.migrate_batch("app", "orders", v1_envs, batch_id="batch-A")
    assert r_a.complete

    # v2 数据；轮换出 v3，v2 archived；batch-B 迁 v2->v3，其中一项先失败
    v2_envs = [svc.encrypt("app", "orders", b"v2-a"),
               svc.encrypt("app", "orders", b"v2-b")]
    cipher.fail_once(v2_envs[1].ciphertext)
    svc.rotate_key("admin", "orders")  # active=v3
    r = svc.migrate_batch("app", "orders", v2_envs, batch_id="batch-B")
    assert len(r.failed) == 1 and r.failed[0].source_version == 2

    # v1 自己名下已无未成功项，但同密钥 v2 还有 FAILED -> v1/v2 退役都必须被拦
    for ver in (1, 2):
        with pytest.raises(RetirementBlockedError) as exc_info:
            svc.retire_key("admin", "orders", ver)
        msg = str(exc_info.value)
        logger.info("退役 v%d 被拦(跨版本把关): code=%s message=%s",
                    ver, exc_info.value.code, msg)
        assert exc_info.value.code == "retirement_blocked"
        # 明细说清：批次、项、来源版本、卡住的状态
        assert "batch-B" in msg
        assert "source_version=2" in msg
        assert "status=failed" in msg
        assert "1 ciphertext item(s)" in msg
        assert svc.keystore.get_version("orders", ver).status is KeyStatus.ARCHIVED

    # 全部迁成功后把关放行：先退役 v1（此前一直被 v2 的失败项挡着）
    r_b = svc.migrate_batch("app", "orders", v2_envs, batch_id="batch-B")
    assert r_b.complete
    assert svc.retire_key("admin", "orders", 1) == 1
    logger.info("判定依据: batch-B 失败项清零后 v1 退役成功, v1状态=%s",
                svc.keystore.get_version("orders", 1).status.value)

    # 放行后：v1 已迁到 v2 的数据照常能解（v2 仍 archived）；
    # batch-B 迁到 v3 的数据也能解；原 v1 信封按 key_retired 拒绝。
    for plain, item in zip((b"v1-a", b"v1-b"),
                           sorted(r_a.migrated, key=lambda i: i.index)):
        assert item.target_version == 2
        assert svc.decrypt("app", item.envelope) == plain
    for plain, item in zip((b"v2-a", b"v2-b"),
                           sorted(r_b.migrated, key=lambda i: i.index)):
        assert item.target_version == 3
        assert svc.decrypt("app", item.envelope) == plain
    with pytest.raises(KeyRetiredError):
        svc.decrypt("app", v1_envs[0])

    # v2 此刻仍可退役（整把密钥已无未成功项），退役后 v1->v2 的那批信封随之不可解，
    # 但迁到 v3 的数据不受影响。
    assert svc.retire_key("admin", "orders", 2) == 2
    with pytest.raises(KeyRetiredError):
        svc.decrypt("app", r_a.migrated[0].envelope)
    assert svc.decrypt("app", r_b.migrated[0].envelope) == b"v2-a"
    logger.info("判定依据: 退役放行后已迁数据在其所在版本退役前照常可解, "
                "版本退役后按 key_retired 拒绝, 不影响更新版本上的数据")


def test_retire_blocked_by_failed_item_on_other_version_tampered():
    """别的版本上因篡改停在 FAILED 的项，同样要拦截退役并点出来源版本。"""
    svc = _service()
    v1_env = svc.encrypt("app", "orders", b"v1")
    svc.rotate_key("admin", "orders")  # v2 active
    svc.migrate_batch("app", "orders", [v1_env], batch_id="A")  # v1 项已迁完

    v2_env = svc.encrypt("app", "orders", b"v2")
    svc.rotate_key("admin", "orders")  # v3 active, v2 archived
    tampered = replace(v2_env, tag=b"\x00" * 16)
    r = svc.migrate_batch("app", "orders", [tampered], batch_id="C")
    assert len(r.failed) == 1 and r.failed[0].source_version == 2

    with pytest.raises(RetirementBlockedError) as exc_info:
        svc.retire_key("admin", "orders", 1)
    logger.info("v2 失败项拦截 v1 退役: %s", str(exc_info.value)[:180])
    assert exc_info.value.code == "retirement_blocked"
    assert "source_version=2" in str(exc_info.value)


def test_retire_gate_stable_under_concurrent_rotation_and_retries():
    """并发轮换 + 反复重试迁移期间反复尝试退役：不误放，全部迁完后稳定放行。"""
    cipher = FailOnceCipher()
    svc = _service(cipher)
    envs = [svc.encrypt("app", "orders", f"c-{i}".encode()) for i in range(10)]
    svc.rotate_key("admin", "orders")
    for e in envs[:3]:  # 前 3 项先失败，批次里存在 FAILED 项
        cipher.fail_once(e.ciphertext)

    stop = threading.Event()
    improper_retirements: list[int] = []
    rotations = 0
    lock = threading.Lock()

    def rotator():
        nonlocal rotations
        while not stop.is_set():
            if svc.keystore.get_active("orders").version < 6:
                svc.rotate_key("admin", "orders")
                with lock:
                    rotations += 1

    def migrator():
        while not stop.is_set():
            if svc.migrate_batch("app", "orders", envs, batch_id="bulk").complete:
                return

    def retirer():
        while not stop.is_set():
            try:
                svc.retire_key("admin", "orders", 1)
            except RetirementBlockedError:
                continue
            # 一旦放行，必须是全部项已迁成功（状态锁保证二者一致）
            if not svc.migrate_batch("app", "orders", envs,
                                     batch_id="bulk").complete:
                improper_retirements.append(1)
            return

    threads = [threading.Thread(target=rotator),
               threading.Thread(target=migrator),
               threading.Thread(target=retirer)]
    for t in threads:
        t.start()
    threads[2].join(timeout=15)
    stop.set()
    threads[0].join()
    threads[1].join()

    final = svc.migrate_batch("app", "orders", envs, batch_id="bulk")
    logger.info("并发把关结果: rotations=%d 批次完成=%s 误放行=%d v1状态=%s",
                rotations, final.complete, len(improper_retirements),
                svc.keystore.get_version("orders", 1).status.value)
    assert not improper_retirements
    assert final.complete
    assert svc.keystore.get_version("orders", 1).status is KeyStatus.RETIRED
    # 已迁数据在并发轮换后全部可解回原文
    plain_by_fp = {i.fingerprint: f"c-{i.index}".encode() for i in final.migrated}
    for item in final.migrated:
        assert svc.decrypt("app", item.envelope) == plain_by_fp[item.fingerprint]
