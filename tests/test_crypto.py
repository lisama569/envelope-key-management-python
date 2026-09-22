"""信封加密原语测试：往返、AAD、三层可区分篡改。"""

from __future__ import annotations

import base64 as b64
import json
import logging

import pytest

from ekm import crypto
from ekm.errors import (
    AadTamperedError,
    CiphertextTamperedError,
    MalformedEnvelopeError,
    MetadataTamperedError,
)

logger = logging.getLogger(__name__)

KEY_ID = "kms-key-1"
VERSION = 3


@pytest.fixture()
def version_key() -> bytes:
    secret = crypto.generate_master_secret()
    key = crypto.derive_version_key(secret, KEY_ID, VERSION)
    logger.info("准备版本密钥 key_id=%s key_version=%s 判定依据=HKDF(master_secret)", KEY_ID, VERSION)
    return key


def _roundtrip(version_key, plaintext=b"hello envelope", aad=b"ctx"):
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=plaintext, aad=aad,
    )
    logger.info("加密成功 使用密钥版本 key_id=%s key_version=%s", env.key_id, env.key_version)
    out = crypto.decrypt_blob(
        version_key=version_key,
        envelope=env.to_dict(),
        expected_aad=aad,
    )
    assert out == plaintext
    return env


def test_roundtrip_with_aad(version_key) -> None:
    env = _roundtrip(version_key, b"top secret", b"tenant-42")
    assert env.key_id == KEY_ID and env.key_version == VERSION


def test_empty_aad(version_key) -> None:
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=b"x", aad=b"",
    )
    assert crypto.decrypt_blob(version_key=version_key, envelope=env.to_dict()) == b"x"


def test_version_isolation(version_key) -> None:
    # 不同版本密钥不能解密（HAT 首先失败）-> 元数据/密钥不匹配
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=b"x", aad=b"",
    ).to_dict()
    other = crypto.derive_version_key(crypto.generate_master_secret(), KEY_ID, VERSION)
    with pytest.raises(MetadataTamperedError):
        crypto.decrypt_blob(version_key=other, envelope=env)


def test_malformed_envelope(version_key) -> None:
    with pytest.raises(MalformedEnvelopeError):
        crypto.decrypt_blob(version_key=version_key, envelope={"key_id": "x"})


def test_tamper_key_version_is_metadata(version_key) -> None:
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=b"secret", aad=b"ctx",
    ).to_dict()
    env["key_version"] = VERSION + 1
    logger.info("篡改 key_version=%s -> %s，判定依据=HAT 头标签比对", VERSION, env["key_version"])
    with pytest.raises(MetadataTamperedError) as ei:
        crypto.decrypt_blob(version_key=version_key, envelope=env)
    logger.info("拒绝原因=%s", ei.value.code)


def test_tamper_wrapped_dek_is_metadata(version_key) -> None:
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=b"secret", aad=b"ctx",
    ).to_dict()
    raw = bytearray(b64.b64decode(env["wrapped_dek"]))
    raw[13] ^= 0x01
    env["wrapped_dek"] = b64.b64encode(bytes(raw)).decode()
    logger.info("篡改 wrapped_dek 第13字节，判定依据=HAT通过但封装GCM认证失败")
    with pytest.raises(MetadataTamperedError) as ei:
        crypto.decrypt_blob(version_key=version_key, envelope=env)
    logger.info("拒绝原因=%s", ei.value.code)


def test_tamper_aad_is_distinct(version_key) -> None:
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=b"secret", aad=b"ctx",
    ).to_dict()
    env["aad"] = b64.b64encode(b"CTX").decode()
    logger.info("篡改 aad，判定依据=AAT(DEK派生密钥) 比对")
    with pytest.raises(AadTamperedError) as ei:
        crypto.decrypt_blob(version_key=version_key, envelope=env)
    logger.info("拒绝原因=%s", ei.value.code)


def test_tamper_aat_is_aad_error(version_key) -> None:
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=b"secret", aad=b"ctx",
    ).to_dict()
    raw = bytearray(b64.b64decode(env["aat"]))
    raw[0] ^= 0xFF
    env["aat"] = b64.b64encode(bytes(raw)).decode()
    with pytest.raises(AadTamperedError) as ei:
        crypto.decrypt_blob(version_key=version_key, envelope=env)
    logger.info("篡改 aat 拒绝原因=%s", ei.value.code)


def test_expected_aad_mismatch(version_key) -> None:
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=b"secret", aad=b"ctx-A",
    ).to_dict()
    with pytest.raises(AadTamperedError):
        crypto.decrypt_blob(version_key=version_key, envelope=env, expected_aad=b"ctx-B")


def test_tamper_ciphertext_is_distinct(version_key) -> None:
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=b"secret", aad=b"ctx",
    ).to_dict()
    raw = bytearray(b64.b64decode(env["ciphertext"]))
    raw[0] ^= 0x01
    env["ciphertext"] = b64.b64encode(bytes(raw)).decode()
    logger.info("篡改 ciphertext 首字节，判定依据=数据GCM认证失败（HAT/AAT均不覆盖密文）")
    with pytest.raises(CiphertextTamperedError) as ei:
        crypto.decrypt_blob(version_key=version_key, envelope=env)
    logger.info("拒绝原因=%s 使用密钥版本=v%s", ei.value.code, VERSION)


def test_tamper_iv_is_ciphertext_error(version_key) -> None:
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=b"secret", aad=b"ctx",
    ).to_dict()
    raw = bytearray(b64.b64decode(env["iv"]))
    raw[0] ^= 0x01
    env["iv"] = b64.b64encode(bytes(raw)).decode()
    with pytest.raises(CiphertextTamperedError):
        crypto.decrypt_blob(version_key=version_key, envelope=env)


def test_envelope_is_json_serializable(version_key) -> None:
    env = crypto.encrypt_blob(
        version_key=version_key, key_id=KEY_ID, key_version=VERSION,
        plaintext=b"", aad=b"",
    ).to_dict()
    assert json.loads(json.dumps(env))["key_version"] == VERSION
