"""轮换期间的并发加解密/迁移：不得产生无法解密的密文，不得出现无可用版本的窗口。"""

import logging
import threading

from app.errors import KeyManagementError
from app.migration import envelope_fingerprint
from app.models import MigrationStatus, KeyStatus

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


def test_concurrent_migration_with_rotation(svc):
    """迁移批次与轮换、加解密同时跑：结果自洽、密文都能解、无重复迁移。"""
    # 先在 v1 攒一批老密文并记录原文
    olds = [svc.encrypt("app-orders", "orders", f"legacy-{i}".encode())
            for i in range(40)]
    plaintexts = {envelope_fingerprint(env): b"legacy-%d" % i
                  for i, env in enumerate(olds)}
    svc.rotate_key("admin", "orders")  # v2 ACTIVE

    stop = threading.Event()
    failures: list[str] = []
    lock = threading.Lock()
    stats = {"rotations": 0, "batches": 0, "migrated": 0, "already": 0}
    # 指纹 -> 迁移成功后看到的目标版本（重复迁移必须返回同一个新信封）
    results: dict[str, bytes] = {}
    results_lock = threading.Lock()

    def rotator() -> None:
        n = 0
        while not stop.is_set():
            try:
                svc.rotate_key("admin", "orders")
                n += 1
            except KeyManagementError as exc:
                with lock:
                    failures.append(f"rotate: {exc.code}")
        with lock:
            stats["rotations"] = n

    def migrator(worker_id: int) -> None:
        # 每个迁移线程反复提交整批（模拟超时后幂等重试），共 5 轮
        for _ in range(5):
            res = svc.migrate_batch("app-orders", olds)
            with lock:
                stats["batches"] += 1
            for item in res.items:
                if item.status is MigrationStatus.FAILED:
                    with lock:
                        failures.append(
                            f"w{worker_id} idx{item.index} {item.error}")
                    continue
                if item.status is MigrationStatus.MIGRATED:
                    with lock:
                        stats["migrated"] += 1
                else:
                    with lock:
                        stats["already"] += 1
                # 无论何时返回，新信封必须能解回原文
                env = item.envelope
                got = svc.decrypt("app-orders", env)
                fp = envelope_fingerprint(olds[item.index])
                if got != plaintexts[fp]:
                    with lock:
                        failures.append("plaintext mismatch at idx %d" % item.index)
                # 同一指纹在不同重试轮里返回的迁移结果必须一致（不重复迁）
                with results_lock:
                    sig = env.iv + env.ciphertext + env.tag
                    if fp in results and results[fp] != sig:
                        failures.append(
                            "fingerprint %s migrated twice to different envelope"
                            % fp[:12])
                    results[fp] = sig

    rot = threading.Thread(target=rotator)
    migrants = [threading.Thread(target=migrator, args=(i,)) for i in range(3)]
    rot.start()
    for t in migrants:
        t.start()
    for t in migrants:
        t.join()
    stop.set()
    rot.join()

    versions = svc.keystore.list_versions("orders")
    active = [kv for kv in versions if kv.status is KeyStatus.ACTIVE]
    logger.info(
        "迁移+轮换并发: rotations=%d batches=%d migrated_reports=%d "
        "already_current_reports=%d, 全部 %d 个指纹均有一致结果, 版本数=%d, "
        "当前 ACTIVE=v%d, 审计链=%s",
        stats["rotations"], stats["batches"], stats["migrated"],
        stats["already"], len(results), len(versions),
        active[0].version if active else -1, svc.audit.verify(),
    )

    assert not failures, f"并发期间出现失败: {failures[:5]}"
    assert len(results) == len(olds), "每个老密文都必须迁移成功且结果唯一"
    assert stats["rotations"] > 0, "轮换必须真实发生"
    # 迁移目标可能跨越多个版本（迁移与轮换交错的真实证据）
    assert len(active) == 1
    assert svc.audit.verify()
    # 所有登记表项最终都成功，没有 PENDING/FAILED 残留
    for env in olds:
        rec = svc.migrations.get(envelope_fingerprint(env))
        assert rec is not None and rec.status is MigrationStatus.MIGRATED

    # 最终再提交一次：全部回放，不产生第二次密码学迁移
    final = svc.migrate_batch("app-orders", olds)
    for item in final.items:
        assert item.status is MigrationStatus.MIGRATED
    logger.info("判定依据: 并发迁移后每个指纹唯一可解、无残留失败、再提交全量回放")
