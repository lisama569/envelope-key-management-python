"""端到端篡改与越权边界：三类篡改原因可区分、越权被拒、绝不返回错误明文。"""

from __future__ import annotations

import base64 as b64
import logging

import pytest

from ekm.errors import (
    AadTamperedError,
    AuthenticationError,
    AuthorizationError,
    CiphertextTamperedError,
    MetadataTamperedError,
)

logger = logging.getLogger(__name__)


@pytest.fixture()
def envelope(service) -> dict:
    service.create_key(actor="admin", key_id="k1")
    env = service.encrypt(actor="crypto-a", key_id="k1",
                          plaintext=b"secret-value", aad=b"tenant-7")
    assert env["key_version"] == 1
    return env


def test_tamper_key_version(service, envelope) -> None:
    envelope["key_version"] = 999
    # 版本 999 不存在 -> 先命中 not-found；这里改用存在但不匹配的版本验证头部层
    envelope["key_version"] = 1  # 先轮换制造版本 2
    service.rotate_key(actor="admin", key_id="k1")
    # 用 v1 的密文伪装成 v2：HAT 用 v2 密钥验证 v1 头部失败
    envelope["key_version"] = 2
    with pytest.raises(MetadataTamperedError) as ei:
        service.decrypt(actor="crypto-a", envelope=envelope)
    logger.info("篡改 key_version v1->v2 拒绝 code=%s 判定依据=HAT 头部标签",
                ei.value.code)


def test_tamper_wrapped_dek(service, envelope) -> None:
    raw = bytearray(b64.b64decode(envelope["wrapped_dek"]))
    raw[12] ^= 0xFF
    envelope["wrapped_dek"] = b64.b64encode(bytes(raw)).decode()
    with pytest.raises(MetadataTamperedError) as ei:
        service.decrypt(actor="crypto-a", envelope=envelope)
    logger.info("篡改 wrapped_dek 拒绝 code=%s 判定依据=封装 GCM 认证失败",
                ei.value.code)


def test_tamper_aad(service, envelope) -> None:
    envelope["aad"] = b64.b64encode(b"tenant-8").decode()
    with pytest.raises(AadTamperedError) as ei:
        service.decrypt(actor="crypto-a", envelope=envelope)
    logger.info("篡改 aad 拒绝 code=%s 判定依据=AAT(派生自DEK) 比对", ei.value.code)


def test_tamper_ciphertext(service, envelope) -> None:
    raw = bytearray(b64.b64decode(envelope["ciphertext"]))
    raw[0] ^= 0x01
    envelope["ciphertext"] = b64.b64encode(bytes(raw)).decode()
    with pytest.raises(CiphertextTamperedError) as ei:
        service.decrypt(actor="crypto-a", envelope=envelope)
    logger.info("篡改 ciphertext 拒绝 code=%s 判定依据=数据 GCM 标签，且未返回任何明文",
                ei.value.code)


def test_three_tamper_codes_are_distinct(service) -> None:
    def make_env():
        return service.encrypt(actor="crypto-a", key_id="k1",
                               plaintext=b"secret-value", aad=b"tenant-7")

    service.create_key(actor="admin", key_id="k1")
    codes = set()

    e1 = make_env()
    raw = bytearray(b64.b64decode(e1["wrapped_dek"])); raw[12] ^= 1
    e1["wrapped_dek"] = b64.b64encode(bytes(raw)).decode()
    with pytest.raises(MetadataTamperedError) as x:
        service.decrypt(actor="crypto-a", envelope=e1)
    codes.add(x.value.code)

    e2 = make_env()
    e2["aad"] = b64.b64encode(b"other").decode()
    with pytest.raises(AadTamperedError) as x:
        service.decrypt(actor="crypto-a", envelope=e2)
    codes.add(x.value.code)

    e3 = make_env()
    raw = bytearray(b64.b64decode(e3["ciphertext"])); raw[0] ^= 1
    e3["ciphertext"] = b64.b64encode(bytes(raw)).decode()
    with pytest.raises(CiphertextTamperedError) as x:
        service.decrypt(actor="crypto-a", envelope=e3)
    codes.add(x.value.code)

    assert codes == {
        "EKM_METADATA_TAMPERED",
        "EKM_AAD_TAMPERED",
        "EKM_CIPHERTEXT_TAMPERED",
    }
    logger.info("三类篡改错误互不相同: %s", sorted(codes))


def test_anonymous_denied(service, envelope) -> None:
    with pytest.raises(AuthenticationError):
        service.decrypt(actor=None, envelope=envelope)
    with pytest.raises(AuthenticationError):
        service.encrypt(actor=None, key_id="k1", plaintext=b"x")


def test_action_denied(service, envelope) -> None:
    # auditor 只有 key.read，不能解密
    with pytest.raises(AuthorizationError) as ei:
        service.decrypt(actor="auditor", envelope=envelope)
    assert ei.value.details["reason"] == "ACTION_DENIED"
    logger.info("auditor 解密被拒 reason=ACTION_DENIED")


def test_key_scope_denied(service, envelope) -> None:
    # crypto-b 只能访问 k3，拿 k1 的密文来解密 -> 范围越权
    with pytest.raises(AuthorizationError) as ei:
        service.decrypt(actor="crypto-b", envelope=envelope)
    assert ei.value.details["reason"] == "KEY_SCOPE_DENIED"
    logger.info("crypto-b 解 k1 密文被拒 reason=KEY_SCOPE_DENIED（越权不触碰密钥）")


def test_rotation_requires_admin(service) -> None:
    service.create_key(actor="admin", key_id="k1")
    with pytest.raises(AuthorizationError):
        service.rotate_key(actor="crypto-a", key_id="k1")
