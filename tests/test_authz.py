"""越权与超出授权密钥范围的请求须以可区分的原因被拒绝。"""

import logging

import pytest

from app.errors import AuthorizationError, KeyScopeError

logger = logging.getLogger("kms.test")


def test_unknown_caller_rejected(svc):
    with pytest.raises(AuthorizationError) as exc_info:
        svc.encrypt("ghost", "orders", b"x")
    logger.info("判定依据: 未注册调用方 -> code=%s", exc_info.value.code)
    assert exc_info.value.code == "authorization_error"


def test_caller_outside_key_scope_rejected(svc):
    svc.create_key("admin", "payments")
    with pytest.raises(KeyScopeError) as exc_info:
        svc.encrypt("app-orders", "payments", b"x")
    logger.info("判定依据: app-orders 不在 payments 授权范围 -> code=%s (与 authorization_error 可区分)",
                exc_info.value.code)
    assert exc_info.value.code == "key_scope_error"


def test_rotate_without_permission_rejected(svc):
    with pytest.raises(AuthorizationError) as exc_info:
        svc.rotate_key("app-orders", "orders")
    logger.info("判定依据: app-orders 无 rotate 权限 -> code=%s", exc_info.value.code)
    assert exc_info.value.code == "authorization_error"


def test_create_without_permission_rejected(svc):
    with pytest.raises(AuthorizationError):
        svc.create_key("app-orders", "orders")
    logger.info("判定依据: app-orders 无 create 权限 -> authorization_error")


def test_authorized_operations_succeed(svc):
    env = svc.encrypt("app-orders", "orders", b"ok")
    assert svc.decrypt("app-orders", env) == b"ok"
    v = svc.rotate_key("admin", "orders")
    logger.info("授权内操作成功: rotate -> version %d", v)
    assert v == 2


def test_audit_chain_consistent_after_repeated_and_denied_calls(svc):
    """重复/越权调用后，密钥状态与审计记录仍自洽：拒绝的操作不留状态变更。"""
    svc.rotate_key("admin", "orders")
    svc.rotate_key("admin", "orders")
    for _ in range(3):
        with pytest.raises(AuthorizationError):
            svc.rotate_key("app-orders", "orders")

    versions = svc.keystore.list_versions("orders")
    active = [kv for kv in versions if kv.status.value == "active"]
    records = svc.audit.records()
    rotates = [r for r in records if r.action == "rotate_key"]
    logger.info("密钥状态: %s; 审计 rotate 记录 %d 条, 链校验=%s",
                [(kv.version, kv.status.value) for kv in versions],
                len(rotates), svc.audit.verify())

    assert len(active) == 1 and active[0].version == 3
    assert len(rotates) == 2, "被拒绝的越权调用不得产生状态变更审计"
    assert svc.audit.verify(), "审计哈希链必须自洽"
    assert [r.seq for r in records] == list(range(1, len(records) + 1)), "序号连续无空洞"
