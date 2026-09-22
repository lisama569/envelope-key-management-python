"""骨架冒烟测试：确认各模块可导入、类型可用。"""

from app.service import KeyManagementService
from app.authz import Caller
from app.models import KeyStatus


def test_skeleton_imports():
    svc = KeyManagementService()
    assert svc.audit is not None
    assert KeyStatus.ACTIVE.value == "active"
    assert Caller(name="dev").name == "dev"
