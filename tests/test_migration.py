"""历史密文迁移：迁到当前版本、格式不变、幂等重试、中断可恢复。"""

import logging

import pytest

from app.crypto import EnvelopeCipher
from app.errors import IntegrityError
from app.authz import Caller
from app.models import Envelope, MigrationStatus
from app.service import KeyManagementService

logger = logging.getLogger("kms.test")


@pytest.fixture()
def rotated(svc):
    """v1 上产生一批老密文，随后轮换到 v2。"""
    olds = [
        svc.encrypt("app-orders", "orders", f"secret-{i}".encode(), aad=b"ctx")
        for i in range(4)
    ]
    active = svc.rotate_key("admin", "orders")
    logger.info("准备迁移: %d 个 v%d 老密文, 当前 ACTIVE=v%d",
                len(olds), olds[0].key_version, active)
    return olds, active


def _by_status(result, status):
    return [i for i in result.items if i.status is status]


def test_migrate_batch_moves_old_ciphertext_to_active(svc, rotated):
    olds, active = rotated
    result = svc.migrate_batch("app-orders", olds)

    assert len(result.items) == len(olds)
    migrated = _by_status(result, MigrationStatus.MIGRATED)
    assert len(migrated) == len(olds)
    for item, old in zip(result.items, olds):
        assert item.source_version == 1
        assert item.target_version == active == 2
        # 迁移后的密文与旧密文不同（新 IV/新密钥），但仍是同一种 Envelope 格式
        assert isinstance(item.envelope, Envelope)
        assert item.envelope.key_version == 2
        assert item.envelope != old
        # 迁后能正常解回原文，AAD 保持一致
        assert svc.decrypt("app-orders", item.envelope, aad=b"ctx") \
            == svc.decrypt("app-orders", old, aad=b"ctx")
    logger.info("判定依据: 全部 source=v1 -> target=v2, 解回原文一致, 信封格式未变")


def test_migration_is_idempotent_on_repeated_submission(svc, rotated):
    olds, _ = rotated
    first = svc.migrate_batch("app-orders", olds)
    first_envelopes = [i.envelope for i in first.items]

    # 同一批反复提交：必须回放同一结果，不重新解密/重加密
    for _ in range(3):
        again = svc.migrate_batch("app-orders", olds)
        assert [i.envelope for i in again.items] == first_envelopes
        assert all(i.status is MigrationStatus.MIGRATED for i in again.items)

    # 登记表里每个指纹只有一条记录（不重复迁）
    from app.migration import envelope_fingerprint
    fps = {envelope_fingerprint(e) for e in olds}
    assert all(svc.migrations.get(fp) is not None for fp in fps)
    assert all(svc.migrations.get(fp).attempts == 1 for fp in fps)
    logger.info("判定依据: 重复提交 3 次回放同一新密文, attempts 不增长, 无重复迁移")


def test_failed_items_can_retried_until_success(svc, rotated):
    olds, _ = rotated
    target = olds[0]
    real_cipher = svc._cipher

    class FlakyCipher(EnvelopeCipher):
        """对 target 的前两次解密注入故障（模拟超时/中断），之后恢复。"""

        def __init__(self):
            self.calls = 0

        def decrypt(self, key, envelope, aad=b""):
            if envelope is target and self.calls < 2:
                self.calls += 1
                raise IntegrityError("simulated transient failure")
            return real_cipher.decrypt(key, envelope, aad)

        def encrypt(self, key, plaintext, aad=b""):
            return real_cipher.encrypt(key, plaintext, aad)

    svc._cipher = FlakyCipher()

    r1 = svc.migrate_batch("app-orders", [target])
    assert r1.failed and r1.failed[0].status is MigrationStatus.FAILED
    assert "integrity_error" in r1.failed[0].error
    logger.info("第 1 次迁移失败: %s（可重试，不影响其他密文）", r1.failed[0].error)

    r2 = svc.migrate_batch("app-orders", [target])
    assert r2.failed and r2.failed[0].status is MigrationStatus.FAILED

    r3 = svc.migrate_batch("app-orders", [target])
    assert not r3.failed
    item = r3.items[0]
    assert item.status is MigrationStatus.MIGRATED and item.target_version == 2
    assert svc.decrypt("app-orders", item.envelope, aad=b"ctx") == b"secret-0"

    from app.migration import envelope_fingerprint
    rec = svc.migrations.get(envelope_fingerprint(target))
    assert rec.attempts == 3 and rec.last_error is None
    logger.info("判定依据: 第 3 次重试成功, attempts=%d, 失败记录被成功覆盖", rec.attempts)


def test_batch_mixes_old_current_and_failed(svc, rotated):
    olds, active = rotated
    current_env = svc.encrypt("app-orders", "orders", b"already-new")  # v2
    assert current_env.key_version == active

    result = svc.migrate_batch("app-orders", [olds[0], current_env, olds[1]])
    statuses = [i.status for i in result.items]
    assert statuses == [
        MigrationStatus.MIGRATED,
        MigrationStatus.ALREADY_CURRENT,
        MigrationStatus.MIGRATED,
    ]
    # already_current 项原样返回，且不产生密码学操作
    assert result.items[1].envelope is current_env
    assert result.items[1].target_version == 2
    assert not result.failed
    logger.info("判定依据: 混合批次逐项报告 migrated/already_current, 顺序对齐")


def test_unauthorized_item_fails_without_affecting_batch(svc, rotated):
    olds, active = rotated
    # app-orders 对 orders 有权；伪造一个 payments 信封，逐项授权应失败但不拖垮整批
    foreign = Envelope(
        key_id="payments", key_version=1, iv=b"iv", ciphertext=b"ct",
        tag=b"00" * 16, aad=b"",
    )
    result = svc.migrate_batch("app-orders", [olds[0], foreign, olds[1]])
    assert result.items[0].status is MigrationStatus.MIGRATED
    assert result.items[2].status is MigrationStatus.MIGRATED
    bad = result.items[1]
    assert bad.status is MigrationStatus.FAILED
    assert bad.error and "key_scope_error" in bad.error
    logger.info("判定依据: 越权项逐项失败(%s), 同批其余项正常迁移", bad.error)


def test_migration_progress_recovered_after_crash(tmp_path):
    """迁移中途进程被杀：重启后从断掉处接着迁，已迁好的不重迁。"""
    state_dir = str(tmp_path / "state")
    svc = KeyManagementService(state_dir=state_dir)
    svc.authorizer.register(Caller(
        name="admin", allowed_key_ids=frozenset({"orders"}),
        can_rotate=True, can_create=True))
    svc.authorizer.register(Caller(name="app-orders", allowed_key_ids=frozenset({"orders"})))
    svc.create_key("admin", "orders")
    olds = [svc.encrypt("app-orders", "orders", f"k-{i}".encode()) for i in range(3)]
    svc.rotate_key("admin", "orders")

    # 先迁成功 2 个
    done = svc.migrate_batch("app-orders", olds[:2])
    migrated_envelopes = [i.envelope for i in done.items]
    # 第三个在处理中途崩溃：直接在登记表制造 PROCESSING 残留
    from app.migration import envelope_fingerprint
    fp2 = envelope_fingerprint(olds[2])
    svc.migrations.begin(fp2, "orders", 1)
    assert svc.migrations.get(fp2).status is MigrationStatus.PROCESSING

    # 模拟重启
    svc2 = KeyManagementService(state_dir=state_dir)
    resumed = svc2.migrate_batch("app-orders", olds)  # 整批重新提交
    statuses = [i.status for i in resumed.items]
    assert statuses == [MigrationStatus.MIGRATED, MigrationStatus.MIGRATED,
                        MigrationStatus.MIGRATED]
    # 前两个回放旧结果，第三个是新迁的
    assert resumed.items[0].envelope == migrated_envelopes[0]
    assert resumed.items[1].envelope == migrated_envelopes[1]
    assert resumed.items[2].envelope.key_version == 2
    for i in range(3):
        assert svc2.decrypt("app-orders", resumed.items[i].envelope) == f"k-{i}".encode()
    assert svc2.audit.verify()
    logger.info("判定依据: PROCESSING 残留重启回退 PENDING, 已迁项回放, 第 3 项续迁成功")
