"""重启恢复：调用方授权（可用密钥范围、操作权限）必须和密钥/迁移/退役状态一起保留。"""

import logging
import os
import tempfile

import pytest

from app.authz import Caller
from app.errors import AuthorizationError, KeyScopeError
from app.persistence import JsonStateStore
from app.service import KeyManagementService

logger = logging.getLogger("kms.test")


@pytest.fixture()
def state_path():
    return os.path.join(tempfile.mkdtemp(), "kms-state.json")


def test_callers_survive_restart_without_reregistering(state_path):
    """登记调用方 -> 建密钥/加解密 -> 重启（不再登记）：谁能做什么完全不变。"""
    store = JsonStateStore(state_path)
    svc = KeyManagementService(state_store=store)
    svc.register_caller(Caller(
        name="admin", allowed_key_ids=frozenset({"orders", "payments"}),
        can_rotate=True, can_create=True,
    ))
    svc.register_caller(Caller(name="app-orders",
                               allowed_key_ids=frozenset({"orders"})))
    svc.register_caller(Caller(name="app-payments",
                               allowed_key_ids=frozenset({"payments"})))

    svc.create_key("admin", "orders")
    env = svc.encrypt("app-orders", "orders", b"persist-me")
    svc.rotate_key("admin", "orders")
    migrated = svc.migrate_batch("app-orders", "orders", [env],
                                 batch_id="B").migrated[0].envelope
    svc.retire_key("admin", "orders", 1)
    logger.info("重启前: orders 已有 v1(retired)/v2(active), 迁移批次 complete")

    # 重启：只给状态文件，不重新登记任何调用方
    svc2 = KeyManagementService(state_store=JsonStateStore(state_path))

    # 授权关系原样恢复：范围内操作照常可用
    assert svc2.decrypt("app-orders", migrated) == b"persist-me"
    new_env = svc2.encrypt("app-orders", "orders", b"after-restart")
    assert svc2.decrypt("app-orders", new_env) == b"after-restart"
    assert svc2.rotate_key("admin", "orders") == 3
    # 权限位也保留：无 rotate 权限的调用方仍被拒
    with pytest.raises(AuthorizationError) as exc:
        svc2.rotate_key("app-orders", "orders")
    assert exc.value.code == "authorization_error"
    # 密钥范围也保留：跨范围访问仍是 key_scope_error
    with pytest.raises(KeyScopeError):
        svc2.encrypt("app-payments", "orders", b"x")
    # 未登记过的调用方依然不认识
    with pytest.raises(AuthorizationError):
        svc2.encrypt("ghost", "orders", b"x")
    logger.info("判定依据: 重启后未重新登记, app-orders 加解密/迁移结果可用, "
                "权限位与密钥范围依旧, 未知调用方仍被拒")
    assert svc2.audit.verify()


def test_authz_scope_change_persists_across_restart(state_path):
    """更新调用方授权范围后重启：以最新声明为准。"""
    svc = KeyManagementService(state_store=JsonStateStore(state_path))
    svc.register_caller(Caller(name="admin",
                               allowed_key_ids=frozenset({"orders", "payments"}),
                               can_create=True, can_rotate=True))
    svc.create_key("admin", "orders")
    svc.create_key("admin", "payments")
    svc.register_caller(Caller(name="app", allowed_key_ids=frozenset({"orders"})))

    # 扩大授权范围并落盘
    svc.register_caller(Caller(name="app",
                               allowed_key_ids=frozenset({"orders", "payments"})))

    svc2 = KeyManagementService(state_store=JsonStateStore(state_path))
    env = svc2.encrypt("app", "payments", b"now-allowed")
    assert svc2.decrypt("app", env) == b"now-allowed"
    logger.info("判定依据: 调用方授权范围扩大后重启, 新范围内操作生效, 无需重新登记")


def test_restart_does_not_change_who_can_do_what_alongside_migration(state_path):
    """迁移中途重启：调用方、密钥版本、批次进度、退役状态一起自圆其说。"""
    svc = KeyManagementService(state_store=JsonStateStore(state_path))
    svc.register_caller(Caller(name="admin",
                               allowed_key_ids=frozenset({"orders"}),
                               can_create=True, can_rotate=True))
    svc.register_caller(Caller(name="app", allowed_key_ids=frozenset({"orders"})))
    svc.create_key("admin", "orders")
    envs = [svc.encrypt("app", "orders", f"p-{i}".encode()) for i in range(3)]
    svc.rotate_key("admin", "orders")
    svc.migrate_batch("app", "orders", envs[:2], batch_id="part-1")

    svc2 = KeyManagementService(state_store=JsonStateStore(state_path))
    # 不登记任何调用方：迁移与加解密凭恢复的授权直接继续
    r1 = svc2.migrate_batch("app", "orders", envs[:2], batch_id="part-1")
    r2 = svc2.migrate_batch("app", "orders", envs[2:], batch_id="part-2")
    assert len(r1.migrated) == 2 and len(r2.migrated) == 1
    for env, item in zip(envs[:2], sorted(r1.migrated, key=lambda i: i.index)):
        assert svc2.decrypt("app", item.envelope) == f"p-{item.index}".encode()
    assert svc2.retire_key("admin", "orders", 1) == 1
    logger.info("判定依据: 重启后授权/版本/批次进度/退役判定一致, 迁移断点继续并可退役")
