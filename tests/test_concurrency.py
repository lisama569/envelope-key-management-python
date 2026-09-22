"""轮换期间的并发加解密：不得产生无法解密的密文，不得出现无可用版本的窗口。"""

import logging
import threading

from app.errors import KeyManagementError
from app.models import KeyStatus

logger = logging.getLogger("kms.test")

_WORKERS = 8
_ROUNDS = 25


def test_concurrent_encrypt_decrypt_during_rotation(svc):
    """一个线程持续轮换，多个线程并发加解密；所有密文必须可解密回原文。"""
    stop = threading.Event()
    failures: list[str] = []
    lock = threading.Lock()
    used_versions: set[int] = set()
    stats = {"encrypt": 0, "decrypt_ok": 0}

    def rotator() -> None:
        n = 0
        while not stop.is_set():
            svc.rotate_key("admin", "orders")
            n += 1
        with lock:
            stats["rotations"] = n

    def worker(idx: int) -> None:
        for r in range(_ROUNDS):
            payload = f"worker-{idx}-round-{r}".encode()
            try:
                env = svc.encrypt("app-orders", "orders", payload)
                with lock:
                    used_versions.add(env.key_version)
                    stats["encrypt"] += 1
                got = svc.decrypt("app-orders", env)
                if got != payload:
                    with lock:
                        failures.append(f"plaintext mismatch: {got!r} != {payload!r}")
                else:
                    with lock:
                        stats["decrypt_ok"] += 1
            except KeyManagementError as exc:  # 不允许出现任何密钥层错误
                with lock:
                    failures.append(f"worker {idx} round {r}: {exc.code}: {exc}")

    rot = threading.Thread(target=rotator)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(_WORKERS)]
    rot.start()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stop.set()
    rot.join()

    versions = svc.keystore.list_versions("orders")
    active = [kv for kv in versions if kv.status is KeyStatus.ACTIVE]
    logger.info(
        "并发结果: rotations=%d encrypts=%d decrypt_ok=%d, 加密涉及版本=%s, "
        "版本总数=%d, 当前 ACTIVE=v%d, 审计链校验=%s",
        stats.get("rotations"), stats["encrypt"], stats["decrypt_ok"],
        sorted(used_versions),
        len(versions), active[0].version if active else -1,
        svc.audit.verify(),
    )

    assert not failures, f"并发期间出现失败: {failures[:5]}"
    assert stats["encrypt"] == _WORKERS * _ROUNDS
    assert stats["decrypt_ok"] == _WORKERS * _ROUNDS
    assert stats.get("rotations", 0) > 0, "轮换必须真实发生"
    assert len(used_versions) >= 2, "加密应跨越多个密钥版本（轮换与加密真实交错）"
    assert len(active) == 1, "任一时刻只有一个 ACTIVE 版本"
    assert svc.audit.verify(), "并发后审计哈希链仍须自洽"
    seqs = [r.seq for r in svc.audit.records()]
    assert seqs == list(range(1, len(seqs) + 1)), "审计序号连续"


def test_no_window_without_active_version(svc):
    """轮换过程中任意时刻查询都必须能拿到 ACTIVE 版本。"""
    missing: list[bool] = []
    stop = threading.Event()

    def rotator() -> None:
        for _ in range(50):
            svc.rotate_key("admin", "orders")
        stop.set()

    def observer() -> None:
        while not stop.is_set():
            if svc.keystore.get_active("orders") is None:
                missing.append(True)

    rot = threading.Thread(target=rotator)
    obs = threading.Thread(target=observer)
    rot.start(); obs.start()
    rot.join(); obs.join()

    logger.info("判定依据: 50 次轮换期间观察到无 ACTIVE 版本的次数=%d", len(missing))
    assert not missing, "轮换期间出现了无可用版本的窗口"
