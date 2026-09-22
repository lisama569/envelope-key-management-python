"""pytest 夹具：每个用例使用独立临时存储目录的服务。"""

from __future__ import annotations

import pytest

from ekm.service import KeyManagementService


@pytest.fixture()
def service(tmp_path) -> KeyManagementService:
    return KeyManagementService(storage_dir=tmp_path / "ekm")
