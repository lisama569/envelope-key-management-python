import logging

import pytest

from app.authz import Caller
from app.service import KeyManagementService

logger = logging.getLogger("kms.test")


@pytest.fixture()
def svc():
    """预置两个调用方与一把密钥的服务实例。"""
    service = KeyManagementService()
    service.authorizer.register(Caller(
        name="admin", allowed_key_ids=frozenset({"orders", "payments"}),
        can_rotate=True, can_create=True,
    ))
    service.authorizer.register(Caller(
        name="app-orders", allowed_key_ids=frozenset({"orders"}),
    ))
    service.authorizer.register(Caller(
        name="app-payments", allowed_key_ids=frozenset({"payments"}),
    ))
    v = service.create_key("admin", "orders")
    logger.info("fixture: created key 'orders' at version %d", v)
    return service
