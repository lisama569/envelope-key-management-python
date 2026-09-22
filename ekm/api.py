"""FastAPI HTTP 层：把错误分类映射为可区分响应。"""

from __future__ import annotations

from fastapi import FastAPI

from .errors import EKMError
from .service import KeyManagementService


def create_app(service: KeyManagementService | None = None) -> FastAPI:
    app = FastAPI(title="Envelope Key Management")
    # 路由在实现阶段注册
    return app


app = create_app()
