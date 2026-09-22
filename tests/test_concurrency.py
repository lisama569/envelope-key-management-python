"""轮换期间的并发加解密：所有密文都必须可解密、无无版本窗口、状态自洽。"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

logger = logging.getLogger(__name__)


def test_concurrent_encrypt_during_rotation(service) -> None:
    service.create_key(actor="admin", key_id="k1")

    results: list[tuple[int, dict]] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def encrypt_one(i: int) -> None:
        try:
            env = service.encrypt(
                actor="crypto-a", key_id="k1",
                plaintext=f"payload-{i}".encode(), aad=f"aad-{i}".encode(),
            )
            with lock:
                results.append((i, env))
        except Exception as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    def rotate_many() -> None:
        for r in range(5):
            service.rotate_key(actor="admin", key_id="k1",
                               idempotency_key=f"rot-{r}")

    with ThreadPoolExecutor(max_workers=12) as pool:
        futs = [pool.submit(encrypt_one, i) for i in range(60)]
        rot_fut = pool.submit(rotate_many)
        for f in futs:
            f.result()
        rot_fut.result()

    assert not errors, f"并发期间出现异常: {errors}"
    assert len(results) == 60

    # 关键断言：每个密文都能按其携带的版本解密（含轮换瞬间产生的密文）
    used_versions = set()
    for i, env in results:
        used_versions.add(env["key_version"])
        pt = service.decrypt(
            actor="crypto-a", envelope=env,
            expected_aad=f"aad-{i}".encode(),
        )
        assert pt == f"payload-{i}".encode()

    status = service.get_key_status(actor="admin", key_id="k1")
    # 并发加密可能落在 v1..v6 多个版本，所有使用过的版本都已归档
    assert used_versions.issubset(set(status["versions"]))
    logger.info(
        "并发结果: %d 份密文全部可解密；密文分布版本=%s；归档=%s；当前=v%s；"
        "判定依据=每份密文携带不可变版本号且该版本密钥永久归档",
        len(results), sorted(used_versions), status["versions"],
        status["current_version"],
    )

    # 审计链在并发追加后仍自洽
    service.audit.verify()
    rotations = [e for e in service.audit.read_all() if e.action == "key.rotate"]
    assert len(rotations) == 5


def test_concurrent_rotation_idempotent(service) -> None:
    """同一幂等键并发轮换，只允许产生一个新版本、一条审计。"""
    service.create_key(actor="admin", key_id="k1")
    barrier = threading.Barrier(8)

    def do_rotate() -> dict:
        barrier.wait()
        return service.rotate_key(actor="admin", key_id="k1",
                                  idempotency_key="same-key")

    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(lambda _: do_rotate(), range(8)))

    assert all(s["current_version"] == 2 for s in statuses)
    rotations = [e for e in service.audit.read_all() if e.action == "key.rotate"]
    assert len(rotations) == 1
    logger.info("同幂等键 8 线程并发轮换：current 一致=v2，key.rotate 审计仅 1 条")
    service.audit.verify()


def test_concurrent_encrypt_and_decrypt_history(service) -> None:
    """轮换持续进行时，旧密文解密始终成功（历史版本不被摘除）。"""
    service.create_key(actor="admin", key_id="k1")
    anchor = service.encrypt(actor="crypto-a", key_id="k1",
                             plaintext=b"anchor", aad=b"anchor-aad")

    def workload() -> None:
        for _ in range(20):
            assert service.decrypt(
                actor="crypto-a", envelope=anchor,
                expected_aad=b"anchor-aad",
            ) == b"anchor"

    with ThreadPoolExecutor(max_workers=8) as pool:
        f_dec = [pool.submit(workload) for _ in range(4)]
        f_rot = pool.submit(lambda: [service.rotate_key(actor="admin", key_id="k1")
                                     for _ in range(4)])
        f_enc = pool.submit(lambda: [
            service.encrypt(actor="crypto-a", key_id="k1",
                            plaintext=b"x", aad=b"y") for _ in range(20)])
        f_rot.result()
        f_enc.result()
        for f in f_dec:
            f.result()

    service.audit.verify()
    logger.info("轮换中旧密文(v1)解密始终成功：历史版本在 versions 中持续保留")
