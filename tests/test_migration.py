"""历史密文迁移：幂等、失败重试、报告可解释、信封格式不变。"""

import logging

import pytest

from app.crypto import EnvelopeCipher
from app.errors import IntegrityError, MigrationBatchMismatchError
from app.models import MigrationStatus

logger = logging.getLogger("kms.test")


class FlakyCipher(EnvelopeCipher):
    """按密文标记制造一次性失败：模拟迁移中途超时/失败，随后重试成功。"""

    def __init__(self) -> None:
        self.failing_markers: set[bytes] = set()
        self.attempts = 0

    def fail_once(self, marker: bytes) -> None:
        self.failing_markers.add(marker)

    def decrypt(self, key, envelope, aad: bytes = b""):
        self.attempts += 1
        if envelope.ciphertext in self.failing_markers:
            self.failing_markers.discard(envelope.ciphertext)
            raise IntegrityError("simulated transient decrypt failure")
        return super().decrypt(key, envelope, aad)


@pytest.fixture()
def svc_flaky():
    from app.authz import Caller
    from app.service import KeyManagementService

    cipher = FlakyCipher()
    service = KeyManagementService(cipher=cipher)
    service.authorizer.register(Caller(
        name="admin", allowed_key_ids=frozenset({"orders"}),
        can_rotate=True, can_create=True,
    ))
    service.authorizer.register(Caller(name="app-orders", allowed_key_ids=frozenset({"orders"})))
    service.create_key("admin", "orders")
    return service, cipher


def _old_envelopes(service, n):
    envs = [service.encrypt("app-orders", "orders", f"secret-{i}".encode(),
                            aad=f"aad-{i}".encode()) for i in range(n)]
    return envs


def test_migration_reencrypts_to_active_version(svc):
    envs = _old_envelopes(svc, 3)
    svc.rotate_key("admin", "orders")
    active = svc.keystore.get_active("orders").version

    report = svc.migrate_batch("app-orders", "orders", envs, batch_id="batch-1")
    logger.info("迁移报告 batch=%s active=%s 各项: %s",
                report.batch_id, report.active_version,
                [(i.source_version, i.status.value, i.target_version) for i in report.items])

    assert report.complete
    assert active == 2
    assert len(report.migrated) == 3
    assert {i.target_version for i in report.migrated} == {2}
    # 迁移后的密文能解回原文，且 AAD 保持一致，信封结构与原来完全相同
    for src, item in zip(envs, report.migrated):
        out = svc.decrypt("app-orders", item.envelope, aad=src.aad)
        assert out == f"secret-{item.index}".encode()
        assert item.envelope.key_id == src.key_id
        assert item.envelope.key_version == 2
        assert item.envelope.aad == src.aad
        assert set(vars(item.envelope)) == set(vars(src))  # 没多/少字段，用户无感
    logger.info("判定依据: 3 项 v1 密文全部迁到 v2, 原 AAD/信封结构保持, 原文一致")


def test_migration_is_idempotent_on_retry(svc):
    envs = _old_envelopes(svc, 3)
    svc.rotate_key("admin", "orders")

    r1 = svc.migrate_batch("app-orders", "orders", envs, batch_id="B")
    migrated_first = {i.fingerprint: i.envelope for i in r1.migrated}
    r2 = svc.migrate_batch("app-orders", "orders", envs, batch_id="B")
    r3 = svc.migrate_batch("app-orders", "orders", list(reversed(envs)), batch_id="B")

    # 反复提交：没有任何一项被二次迁移（信封对象/字节保持首次迁移结果）
    for rep in (r2, r3):
        assert len(rep.migrated) == 3
        for i in rep.migrated:
            assert i.envelope is migrated_first[i.fingerprint]
    logger.info("判定依据: 同批次提交 3 次（含逆序）, 已迁项零重复迁移, 结果完全一致")


def test_migration_resubmit_with_different_set_rejected(svc):
    envs = _old_envelopes(svc, 3)
    svc.migrate_batch("app-orders", "orders", envs, batch_id="B")
    with pytest.raises(MigrationBatchMismatchError) as exc_info:
        svc.migrate_batch("app-orders", "orders", envs[:2], batch_id="B")
    logger.info("判定依据: 同批次号不同密文集合 -> %s", exc_info.value.code)
    assert exc_info.value.code == "migration_batch_mismatch"


def test_failed_item_retried_until_success(svc_flaky):
    svc, cipher = svc_flaky
    envs = _old_envelopes(svc, 2)
    cipher.fail_once(envs[1].ciphertext)  # 第二项第一次迁移失败
    svc.rotate_key("admin", "orders")

    r1 = svc.migrate_batch("app-orders", "orders", envs, batch_id="B")
    assert not r1.complete
    assert len(r1.migrated) == 1
    failed = r1.failed
    assert len(failed) == 1
    assert failed[0].status is MigrationStatus.FAILED
    assert failed[0].envelope is None
    assert "integrity_error" in failed[0].error
    logger.info("首次迁移: migrated=%d failed=%d, 失败项 error=%s",
                len(r1.migrated), len(r1.failed), failed[0].error)

    # 重试同一批：成功项跳过，失败项续迁成功；已迁结果不被破坏
    r2 = svc.migrate_batch("app-orders", "orders", envs, batch_id="B")
    assert r2.complete and len(r2.migrated) == 2
    first = next(i for i in r2.migrated if i.fingerprint == r1.migrated[0].fingerprint)
    assert first.envelope is r1.migrated[0].envelope
    for src, item in zip(envs, sorted(r2.migrated, key=lambda i: i.index)):
        assert svc.decrypt("app-orders", item.envelope, aad=src.aad) == \
            f"secret-{item.index}".encode()
    logger.info("判定依据: 重试后失败项成功迁到 v2, 已迁项保持原样, 批次整体 complete=%s",
                r2.complete)


def test_already_current_items_marked_not_reencrypted(svc):
    svc.rotate_key("admin", "orders")
    old = svc.encrypt  # noqa
    # 先制造一个 v1 老密文：回退到轮换前不可行，所以直接重造流程
    from app.service import KeyManagementService
    from app.authz import Caller

    fresh = KeyManagementService()
    fresh.authorizer.register(Caller(name="admin",
                                     allowed_key_ids=frozenset({"orders"}),
                                     can_rotate=True, can_create=True))
    fresh.authorizer.register(Caller(name="app-orders",
                                     allowed_key_ids=frozenset({"orders"})))
    fresh.create_key("admin", "orders")
    old_env = fresh.encrypt("app-orders", "orders", b"old")
    fresh.rotate_key("admin", "orders")
    cur_env = fresh.encrypt("app-orders", "orders", b"current")

    report = fresh.migrate_batch("app-orders", "orders", [old_env, cur_env], batch_id="B")
    assert len(report.migrated) == 1
    assert len(report.already_current) == 1
    ac = report.already_current[0]
    assert ac.envelope is cur_env and ac.target_version == 2
    assert report.complete
    logger.info("判定依据: 已是活跃版本的项标记 already_current, 不重新加密, 批次仍算完成")


def test_migration_audited_and_chain_valid(svc):
    envs = _old_envelopes(svc, 2)
    svc.rotate_key("admin", "orders")
    svc.migrate_batch("app-orders", "orders", envs, batch_id="B")
    records = svc.audit.records()
    actions = [r.action for r in records]
    assert "migration_register" in actions and "migration_complete" in actions
    complete = [r for r in records if r.action == "migration_complete"][-1]
    assert "migrated=2" in complete.detail and "complete=True" in complete.detail
    assert svc.audit.verify()
    logger.info("迁移审计: %s", complete.detail)
