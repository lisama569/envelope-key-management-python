"""重启后调用方授权保留：已登记的调用方、可用密钥范围、操作权限随状态落盘。

重启不能改变谁能做什么：已授权调用方重启后照旧能加解密/迁移/轮换，
未授权调用方重启后照旧被拒绝，且无需重新登记。
"""

import logging
import os
import tempfile

import pytest

from app.authz import Caller
from app.errors import AuthorizationError, KeyScopeError
from app.persistence import JsonStateStore
from app.service import KeyManagementService

logger = logging.getLogger("kms.test")


def _boot(state_store: JsonStateStore) -> KeyManagementService:
    """只凭状态文件拉起服务（模拟重启）：不重新登记任何调用方。"""
    return KeyManagementService(state_store=state_store)


@pytest.fixture()
def state_store():
    tmp = tempfile.mkdtemp()
    return JsonStateStore(os.path.join(tmp, "state.json"))


def _seed(state_store: JsonStateStore) -> KeyManagementService:
    svc = KeyManagementService(state_store=state_store)
    svc.authorizer.register(Caller(
        name="admin", allowed_key_ids=frozenset({"orders", "payments"}),
        can_rotate=True, can_create=True,
    ))
    svc.authorizer.register(Caller(
        name="app-orders", allowed_key_ids=frozenset({"orders"})))
    svc.create_key("admin", "orders")
    return svc


def test_authorizations_survive_restart(state_store):
    svc = _seed(state_store)
    env = svc.encrypt("app-orders", "orders", b"before-restart", aad=b"t")
    svc.rotate_key("admin", "orders")
    report = svc.migrate_batch("app-orders", "orders", [env], batch_id="B")
    migrated = report.migrated[0].envelope

    # 重启：不重新登记任何调用方
    svc2 = _boot(state_store)

    # 已授权调用方照旧能解密、加密、迁移
    assert svc2.decrypt("app-orders", migrated, aad=b"t") == b"before-restart"
    env2 = svc2.encrypt("app-orders", "orders", b"after-restart")
    assert svc2.decrypt("app-orders", env2) == b"after-restart"
    r = svc2.migrate_batch("app-orders", "orders", [env], batch_id="B")
    assert r.complete, "重启后已登记调用方应能继续迁移（幂等取回批次）"

    # 管理权限（can_rotate）也保留：重启后可直接轮换/退役
    assert svc2.rotate_key("admin", "orders") == 3
    assert svc2.retire_key("admin", "orders", 1) == 1

    logger.info(
        "判定依据: 重启后未重新登记, admin 轮换到 v3 并退役 v1 成功, "
        "app-orders 加解密/迁移照常")


def test_unauthorized_stays_unauthorized_after_restart(state_store):
    svc = _seed(state_store)
    env = svc.encrypt("app-orders", "orders", b"secret")

    svc2 = _boot(state_store)

    # 从未登记的调用方：重启后仍然未知
    with pytest.raises(AuthorizationError) as exc_info:
        svc2.decrypt("ghost", env)
    assert exc_info.value.code == "authorization_error"

    # 已登记但密钥不在授权范围内：重启后仍然越权
    svc.authorizer.register(Caller(name="outsider",
                                   allowed_key_ids=frozenset({"payments"})))
    svc3 = _boot(state_store)
    with pytest.raises(KeyScopeError) as exc_info:
        svc3.decrypt("outsider", env)
    assert exc_info.value.code == "key_scope_error"

    # 无 rotate 权限的调用方重启后仍不能轮换
    with pytest.raises(AuthorizationError) as exc_info:
        svc3.rotate_key("app-orders", "orders")
    assert exc_info.value.code == "authorization_error"

    logger.info(
        "判定依据: 重启后 unknown caller / 越范围 / 无权限 三类拒绝维持不变: "
        "authorization_error / key_scope_error / authorization_error")


def test_permission_changes_persist_incrementally(state_store):
    """运行中新登记/调整的授权立即落盘，其后的重启按最新授权恢复。"""
    svc = _seed(state_store)
    svc.encrypt("app-orders", "orders", b"x")

    # 运行中登记一个新调用方（不经过任何显式保存动作）
    svc.authorizer.register(Caller(name="auditor",
                                   allowed_key_ids=frozenset({"orders"})))

    svc2 = _boot(state_store)
    caller = svc2.authorizer.get("auditor")
    assert caller is not None
    assert caller.allowed_key_ids == frozenset({"orders"})
    assert not caller.can_rotate and not caller.can_create
    env = svc2.encrypt("auditor", "orders", b"by-auditor")
    assert svc2.decrypt("auditor", env) == b"by-auditor"
    logger.info("判定依据: 运行中登记的 auditor 重启后仍在, 权限范围与登记时一致")
