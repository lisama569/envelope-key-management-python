"""退役把关（整把密钥粒度）：任一版本名下还有未迁成功的项，退役就必须被拦住。

覆盖：
- 被退役版本自己名下的密文都迁完了，但同一密钥别的版本名下还有 FAILED 项
  -> 退役被拦，且错误能点明是哪个批次、哪一项、卡在什么状态；
- 这些项全部迁成功后退役放行，已迁好的数据照常能解；
- 并发轮换 + 反复重试的过程中，把关判定稳定（未迁完期间退役绝不放行）。
"""

import logging
import threading
import time

import pytest

from app.authz import Caller
from app.crypto import EnvelopeCipher
from app.errors import IntegrityError, RetirementBlockedError
from app.models import KeyStatus
from app.service import KeyManagementService

logger = logging.getLogger("kms.test")


class GatedCipher(EnvelopeCipher):
    """对指定密文制造可开关的解密失败：gate 关闭期间一直失败，打开后恢复。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._blocked: set[bytes] = set()
        self._open = False

    def block(self, marker: bytes) -> None:
        with self._lock:
            self._blocked.add(marker)

    def open_gate(self) -> None:
        with self._lock:
            self._open = True

    def decrypt(self, key, envelope, aad: bytes = b""):
        with self._lock:
            denied = not self._open and envelope.ciphertext in self._blocked
        if denied:
            raise IntegrityError("gated transient failure")
        return super().decrypt(key, envelope, aad)


@pytest.fixture()
def svc_gated():
    cipher = GatedCipher()
    service = KeyManagementService(cipher=cipher)
    service.authorizer.register(Caller(
        name="admin", allowed_key_ids=frozenset({"orders"}),
        can_rotate=True, can_create=True,
    ))
    service.authorizer.register(Caller(name="app-orders", allowed_key_ids=frozenset({"orders"})))
    service.create_key("admin", "orders")
    return service, cipher


def _build_two_version_history(svc, cipher):
    """造出 v1、v2 两个归档版本的历史密文；v1 批次迁完，v2 批次留一个 FAILED 项。"""
    e_v1 = svc.encrypt("app-orders", "orders", b"from-v1")
    svc.rotate_key("admin", "orders")          # active v2
    e_v2 = svc.encrypt("app-orders", "orders", b"from-v2")
    svc.rotate_key("admin", "orders")          # active v3；v1/v2 均 archived

    r1 = svc.migrate_batch("app-orders", "orders", [e_v1], batch_id="B-v1")
    assert r1.complete, "v1 名下的批次应一次迁完"

    cipher.block(e_v2.ciphertext)
    r2 = svc.migrate_batch("app-orders", "orders", [e_v2], batch_id="B-v2")
    assert len(r2.failed) == 1, "v2 名下的批次应留下一个 FAILED 项"
    return e_v1, e_v2


def test_retire_blocked_by_failed_item_on_other_version(svc_gated):
    """v1 自己的密文全迁完，但 v2 名下还有 FAILED 项 -> 退役 v1 必须被拦。"""
    svc, cipher = svc_gated
    e_v1, e_v2 = _build_two_version_history(svc, cipher)

    with pytest.raises(RetirementBlockedError) as exc_info:
        svc.retire_key("admin", "orders", 1)
    err = exc_info.value
    message = str(err)
    logger.info(
        "退役被拦: key=orders 目标版本=v1 code=%s 判定依据=%s", err.code, message)
    assert err.code == "retirement_blocked"
    # 能点清是哪个批次、哪一项、卡在什么状态、属于哪个版本
    assert "B-v2" in message
    assert "status=failed" in message
    assert "source_version=v2" in message
    assert svc.keystore.get_version("orders", 1).status is KeyStatus.ARCHIVED

    # 把 v2 名下那一项迁成功后，退役放行
    cipher.open_gate()
    r = svc.migrate_batch("app-orders", "orders", [e_v2], batch_id="B-v2")
    assert r.complete
    assert svc.retire_key("admin", "orders", 1) == 1
    assert svc.keystore.get_version("orders", 1).status is KeyStatus.RETIRED
    # 放行后已迁好的数据照常能解
    assert svc.decrypt("app-orders", r.migrated[0].envelope) == b"from-v2"
    logger.info(
        "判定依据: B-v2 唯一失败项迁成功后退役 v1 放行, 迁到 v%d 的数据仍可解密",
        r.migrated[0].target_version)


def test_retire_guard_stable_under_concurrent_rotation_and_retries(svc_gated):
    """并发轮换 + 迁移反复重试期间，只要还有未成功项，退役判定必须稳定为拒绝。"""
    svc, cipher = svc_gated
    e_v1, e_v2 = _build_two_version_history(svc, cipher)

    stop = threading.Event()
    unexpected: list[str] = []
    stats = {"retire_attempts": 0, "blocked": 0, "rotations": 0, "migrate_runs": 0}
    lock = threading.Lock()

    def retire_attempter():
        while not stop.is_set():
            try:
                svc.retire_key("admin", "orders", 1)
                with lock:
                    unexpected.append("retire succeeded while v2 item still FAILED")
            except RetirementBlockedError:
                with lock:
                    stats["blocked"] += 1
            with lock:
                stats["retire_attempts"] += 1

    def migrator():
        while not stop.is_set():
            svc.migrate_batch("app-orders", "orders", [e_v2], batch_id="B-v2")
            with lock:
                stats["migrate_runs"] += 1

    def rotator():
        while not stop.is_set():
            svc.rotate_key("admin", "orders")
            with lock:
                stats["rotations"] += 1

    threads = [threading.Thread(target=retire_attempter),
               threading.Thread(target=migrator),
               threading.Thread(target=rotator)]
    for t in threads:
        t.start()
    time.sleep(0.4)
    stop.set()
    for t in threads:
        t.join()

    logger.info(
        "并发期间: retire 尝试=%d 被拦=%d 轮换=%d 迁移重试=%d, v1 状态=%s",
        stats["retire_attempts"], stats["blocked"], stats["rotations"],
        stats["migrate_runs"], svc.keystore.get_version("orders", 1).status.value)
    assert not unexpected
    assert stats["retire_attempts"] > 0 and stats["blocked"] == stats["retire_attempts"]
    assert svc.keystore.get_version("orders", 1).status is KeyStatus.ARCHIVED

    # 打开闸门、迁完最后一项后，退役立即放行；已迁数据可解
    cipher.open_gate()
    final = svc.migrate_batch("app-orders", "orders", [e_v2], batch_id="B-v2")
    assert final.complete
    assert svc.retire_key("admin", "orders", 1) == 1
    assert svc.decrypt("app-orders", final.migrated[0].envelope) == b"from-v2"
    logger.info(
        "判定依据: 未迁完期间 %d 次退役全被拦, 全部迁完后退役放行且数据可解",
        stats["blocked"])
