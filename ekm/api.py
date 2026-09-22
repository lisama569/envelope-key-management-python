"""FastAPI HTTP 层：把错误分类映射为带稳定错误码的可区分响应。

身份通过 ``X-Actor`` 头传入（本地模拟，生产应替换为真实鉴权）。
成功响应额外回显 ``key_version``，便于调用方与测试日志核对所用版本。
"""

from __future__ import annotations

import base64
from typing import Annotated

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .errors import EKMError
from .service import KeyManagementService


class CreateKeyRequest(BaseModel):
    key_id: str = Field(min_length=1, max_length=128)


class RotateKeyRequest(BaseModel):
    key_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str | None = None


class EncryptRequest(BaseModel):
    key_id: str = Field(min_length=1, max_length=128)
    plaintext_b64: str
    aad_b64: str = ""


class DecryptRequest(BaseModel):
    envelope: dict
    expected_aad_b64: str | None = None


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def create_app(service: KeyManagementService | None = None) -> FastAPI:
    service = service or KeyManagementService()
    app = FastAPI(title="Envelope Key Management", version="0.1.0")

    @app.exception_handler(EKMError)
    async def _ekm_error_handler(_request, exc: EKMError):  # noqa: ANN202
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unexpected_error_handler(_request, exc: Exception):  # noqa: ANN202
        # base64 等输入错误归入结构错误，不泄露堆栈
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "EKM_MALFORMED_ENVELOPE",
                    "message": f"请求格式不合法: {exc.__class__.__name__}",
                    "details": {},
                }
            },
        )

    @app.post("/keys")
    def create_key(
        body: CreateKeyRequest,
        x_actor: Annotated[str | None, Header(alias="X-Actor")] = None,
    ):
        return service.create_key(actor=x_actor, key_id=body.key_id)

    @app.post("/keys/rotate")
    def rotate_key(
        body: RotateKeyRequest,
        x_actor: Annotated[str | None, Header(alias="X-Actor")] = None,
    ):
        return service.rotate_key(
            actor=x_actor, key_id=body.key_id,
            idempotency_key=body.idempotency_key,
        )

    @app.get("/keys/{key_id}")
    def get_key(
        key_id: str,
        x_actor: Annotated[str | None, Header(alias="X-Actor")] = None,
    ):
        return service.get_key_status(actor=x_actor, key_id=key_id)

    @app.post("/encrypt")
    def encrypt(
        body: EncryptRequest,
        x_actor: Annotated[str | None, Header(alias="X-Actor")] = None,
    ):
        envelope = service.encrypt(
            actor=x_actor, key_id=body.key_id,
            plaintext=_b64d(body.plaintext_b64),
            aad=_b64d(body.aad_b64),
        )
        return {"envelope": envelope, "key_version": envelope["key_version"]}

    @app.post("/decrypt")
    def decrypt(
        body: DecryptRequest,
        x_actor: Annotated[str | None, Header(alias="X-Actor")] = None,
    ):
        expected_aad = _b64d(body.expected_aad_b64) if body.expected_aad_b64 is not None else None
        plaintext = service.decrypt(
            actor=x_actor, envelope=body.envelope, expected_aad=expected_aad,
        )
        return {
            "plaintext_b64": _b64e(plaintext),
            "key_version": body.envelope.get("key_version"),
        }

    @app.get("/audit/verify")
    def audit_verify(x_actor: Annotated[str | None, Header(alias="X-Actor")] = None):
        service.verify_audit(actor=x_actor)
        entries = service.audit.read_all()
        return {"status": "OK", "entries": len(entries)}

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
