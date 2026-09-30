"""HTTP 入口：把 KeyManagementService 暴露为简单的 REST API。"""

from __future__ import annotations

import base64
import binascii
import os

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.authz import Caller
from app.errors import EnvelopeFormatError, KeyManagementError
from app.models import Envelope
from app.persistence import JsonStateStore
from app.service import KeyManagementService

app = FastAPI(title="Local Envelope Key Management")

# 可选：设置 KMS_STATE_FILE 后，密钥/迁移/审计状态落盘，重启可恢复
_state_file = os.environ.get("KMS_STATE_FILE")
service = KeyManagementService(
    state_store=JsonStateStore(_state_file) if _state_file else None
)
# 演示用调用方：admin 可创建/轮换，app-orders 仅可对 orders 加解密。
# 已持久化的授权关系在重启后从状态文件恢复，这里只补齐缺失的默认调用方，
# 不覆盖已有配置（重启不改变谁能做什么）。
if service.authorizer.get("admin") is None:
    service.authorizer.register(Caller(
        name="admin", allowed_key_ids=frozenset({"orders"}),
        can_rotate=True, can_create=True,
    ))
if service.authorizer.get("app-orders") is None:
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
    forbidden = {"authorization_error", "key_scope_error"}
    conflict = {"key_conflict", "migration_batch_mismatch"}
    not_found = {"key_not_found"}
    if exc.code in forbidden:
        status = 403
    elif exc.code in conflict:
        status = 409
    elif exc.code in not_found:
        status = 404
    else:  # retired / retirement_blocked / 完整性 / 格式 / 无活跃版本
        status = 400
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


@app.post("/keys/{key_id}/versions/{version}/retire")
def retire_key(key_id: str, version: int, x_caller: str = Header()) -> dict:
    return {"key_id": key_id, "version": service.retire_key(x_caller, key_id, version)}


class MigrateRequest(BaseModel):
    batch_id: str
    envelopes: list[DecryptRequest]


def _envelope_from_req(req: DecryptRequest) -> Envelope:
    """把请求体转成信封；base64 等解析失败统一转为 EnvelopeFormatError（400），
    不把内部解析异常暴露为 500。"""
    try:
        return Envelope(
            key_id=req.key_id,
            key_version=req.key_version,
            iv=_b64d(req.iv_b64),
            ciphertext=_b64d(req.ciphertext_b64),
            tag=_b64d(req.tag_b64),
            aad=_b64d(req.aad_b64),
        )
    except (ValueError, binascii.Error) as exc:
        raise EnvelopeFormatError(f"malformed envelope encoding: {exc}") from exc


def _envelope_to_json(env: Envelope) -> dict:
    return {
        "key_id": env.key_id,
        "key_version": env.key_version,
        "iv_b64": _b64e(env.iv),
        "ciphertext_b64": _b64e(env.ciphertext),
        "tag_b64": _b64e(env.tag),
        "aad_b64": _b64e(env.aad),
    }


@app.post("/keys/{key_id}/migrate")
def migrate_batch(key_id: str, req: MigrateRequest, x_caller: str = Header()) -> dict:
    """幂等迁移：同一 batch_id + 同一组密文可反复提交，从中断处继续。"""
    envelopes = [_envelope_from_req(e) for e in req.envelopes]
    report = service.migrate_batch(x_caller, key_id, envelopes, req.batch_id)
    return {
        "batch_id": report.batch_id,
        "key_id": report.key_id,
        "active_version": report.active_version,
        "complete": report.complete,
        "counts": {
            "migrated": len(report.migrated),
            "already_current": len(report.already_current),
            "failed": len(report.failed),
            "pending": len(report.pending),
        },
        "items": [
            {
                "index": i.index,
                "fingerprint": i.fingerprint,
                "source_version": i.source_version,
                "target_version": i.target_version,
                "status": i.status.value,
                "envelope": _envelope_to_json(i.envelope) if i.envelope else None,
                "error": i.error,
            }
            for i in report.items
        ],
    }


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
    env = _envelope_from_req(req)
    return {"plaintext_b64": _b64e(service.decrypt(x_caller, env))}


@app.get("/audit/verify")
def audit_verify() -> dict:
    return {"valid": service.audit.verify(), "records": len(service.audit.records())}
