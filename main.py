"""HTTP 入口：把 KeyManagementService 暴露为简单的 REST API。"""

from __future__ import annotations

import base64

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.authz import Caller
from app.errors import KeyManagementError
from app.models import Envelope
from app.service import KeyManagementService

app = FastAPI(title="Local Envelope Key Management")

service = KeyManagementService()
# 演示用调用方：admin 可创建/轮换，app-orders 仅可对 orders 加解密
service.authorizer.register(Caller(
    name="admin", allowed_key_ids=frozenset({"orders"}),
    can_rotate=True, can_create=True,
))
service.authorizer.register(Caller(name="app-orders", allowed_key_ids=frozenset({"orders"})))


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


class CreateKeyRequest(BaseModel):
    key_id: str


class EncryptRequest(BaseModel):
    key_id: str
    plaintext_b64: str
    aad_b64: str = ""


class DecryptRequest(BaseModel):
    key_id: str
    key_version: int
    iv_b64: str
    ciphertext_b64: str
    tag_b64: str
    aad_b64: str = ""


@app.exception_handler(KeyManagementError)
def _kms_error_handler(request, exc: KeyManagementError):  # noqa: ANN001
    status = 403 if exc.code in ("authorization_error", "key_scope_error") else 400
    return JSONResponse(
        status_code=status,
        content={"code": exc.code, "message": str(exc)},
    )


@app.post("/keys", status_code=201)
def create_key(req: CreateKeyRequest, x_caller: str = Header()) -> dict:
    return {"key_id": req.key_id, "version": service.create_key(x_caller, req.key_id)}


@app.post("/keys/{key_id}/rotate")
def rotate_key(key_id: str, x_caller: str = Header()) -> dict:
    return {"key_id": key_id, "version": service.rotate_key(x_caller, key_id)}


@app.post("/encrypt")
def encrypt(req: EncryptRequest, x_caller: str = Header()) -> dict:
    env = service.encrypt(x_caller, req.key_id, _b64d(req.plaintext_b64), _b64d(req.aad_b64))
    return {
        "key_id": env.key_id,
        "key_version": env.key_version,
        "iv_b64": _b64e(env.iv),
        "ciphertext_b64": _b64e(env.ciphertext),
        "tag_b64": _b64e(env.tag),
        "aad_b64": _b64e(env.aad),
    }


@app.post("/decrypt")
def decrypt(req: DecryptRequest, x_caller: str = Header()) -> dict:
    env = Envelope(
        key_id=req.key_id,
        key_version=req.key_version,
        iv=_b64d(req.iv_b64),
        ciphertext=_b64d(req.ciphertext_b64),
        tag=_b64d(req.tag_b64),
        aad=_b64d(req.aad_b64),
    )
    return {"plaintext_b64": _b64e(service.decrypt(x_caller, env))}


@app.get("/audit/verify")
def audit_verify() -> dict:
    return {"valid": service.audit.verify(), "records": len(service.audit.records())}
