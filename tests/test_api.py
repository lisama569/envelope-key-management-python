"""HTTP API 端到端：创建/轮换/加解密、历史解密、三类篡改与越权错误码。"""

from __future__ import annotations

import base64 as b64
import logging

import pytest
from fastapi.testclient import TestClient

from ekm.api import create_app

logger = logging.getLogger(__name__)


@pytest.fixture()
def client(service) -> TestClient:
    return TestClient(create_app(service))


def _enc(client, actor, key_id, pt, aad=b""):
    r = client.post("/encrypt", headers={"X-Actor": actor}, json={
        "key_id": key_id,
        "plaintext_b64": b64.b64encode(pt).decode(),
        "aad_b64": b64.b64encode(aad).decode(),
    })
    assert r.status_code == 200, r.text
    return r.json()


def test_full_flow_and_history(client) -> None:
    r = client.post("/keys", headers={"X-Actor": "admin"}, json={"key_id": "k1"})
    assert r.status_code == 200 and r.json()["current_version"] == 1

    e1 = _enc(client, "crypto-a", "k1", b"old-secret", b"t1")
    assert e1["key_version"] == 1

    r = client.post("/keys/rotate", headers={"X-Actor": "admin"},
                    json={"key_id": "k1", "idempotency_key": "r1"})
    assert r.json()["current_version"] == 2
    # 幂等重试
    r2 = client.post("/keys/rotate", headers={"X-Actor": "admin"},
                     json={"key_id": "k1", "idempotency_key": "r1"})
    assert r2.json()["current_version"] == 2

    e2 = _enc(client, "crypto-a", "k1", b"new-secret", b"t2")
    assert e2["key_version"] == 2

    for env, aad, pt in [(e1["envelope"], b"t1", b"old-secret"),
                         (e2["envelope"], b"t2", b"new-secret")]:
        r = client.post("/decrypt", headers={"X-Actor": "crypto-a"}, json={
            "envelope": env,
            "expected_aad_b64": b64.b64encode(aad).decode(),
        })
        assert r.status_code == 200
        assert b64.b64decode(r.json()["plaintext_b64"]) == pt
    logger.info("API: v1 历史密文与 v2 新密文均解密成功，响应回显 key_version")


def test_anonymous_and_forbidden_codes(client) -> None:
    client.post("/keys", headers={"X-Actor": "admin"}, json={"key_id": "k1"})

    r = client.post("/encrypt", json={"key_id": "k1", "plaintext_b64": ""})
    assert r.status_code == 401 and r.json()["error"]["code"] == "EKM_UNAUTHENTICATED"

    r = client.post("/keys/rotate", headers={"X-Actor": "crypto-a"},
                    json={"key_id": "k1"})
    assert r.status_code == 403
    body = r.json()["error"]
    assert body["code"] == "EKM_FORBIDDEN"
    assert body["details"]["reason"] == "ACTION_DENIED"

    # crypto-b 越密钥范围
    r = _enc_raw(client, "crypto-b", "k1")
    assert r.status_code == 403
    assert r.json()["error"]["details"]["reason"] == "KEY_SCOPE_DENIED"
    logger.info("API 越权返回 403 + 可区分 reason，不执行任何密钥操作")


def _enc_raw(client, actor, key_id):
    return client.post("/encrypt", headers={"X-Actor": actor}, json={
        "key_id": key_id, "plaintext_b64": b64.b64encode(b"x").decode(),
        "aad_b64": "",
    })


def test_tamper_error_codes(client) -> None:
    client.post("/keys", headers={"X-Actor": "admin"}, json={"key_id": "k1"})
    env = _enc(client, "crypto-a", "k1", b"secret", b"ctx")["envelope"]

    # AAD 篡改
    tampered = dict(env)
    tampered["aad"] = b64.b64encode(b"CTX").decode()
    r = client.post("/decrypt", headers={"X-Actor": "crypto-a"},
                    json={"envelope": tampered})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "EKM_AAD_TAMPERED"

    # 密文篡改
    tampered = dict(env)
    raw = bytearray(b64.b64decode(tampered["ciphertext"])); raw[0] ^= 1
    tampered["ciphertext"] = b64.b64encode(bytes(raw)).decode()
    r = client.post("/decrypt", headers={"X-Actor": "crypto-a"},
                    json={"envelope": tampered})
    assert r.json()["error"]["code"] == "EKM_CIPHERTEXT_TAMPERED"

    # 元数据（key_version）篡改为不存在版本 -> not found
    tampered = dict(env)
    tampered["key_version"] = 42
    r = client.post("/decrypt", headers={"X-Actor": "crypto-a"},
                    json={"envelope": tampered})
    assert r.json()["error"]["code"] == "EKM_KEY_VERSION_NOT_FOUND"
    logger.info("API 篡改/AAD/密文/未知版本分别返回不同错误码")


def test_audit_verify_endpoint(client) -> None:
    client.post("/keys", headers={"X-Actor": "admin"}, json={"key_id": "k1"})
    client.post("/keys/rotate", headers={"X-Actor": "admin"}, json={"key_id": "k1"})
    r = client.get("/audit/verify", headers={"X-Actor": "admin"})
    assert r.status_code == 200 and r.json()["status"] == "OK"
    assert r.json()["entries"] >= 2
    # 非管理员不可核验
    r = client.get("/audit/verify", headers={"X-Actor": "crypto-a"})
    assert r.status_code == 403
