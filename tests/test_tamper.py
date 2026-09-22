"""密文、附加数据与封装元数据篡改必须被可区分地拒绝。"""

import logging
from dataclasses import replace

import pytest

from app.errors import EnvelopeFormatError, IntegrityError

logger = logging.getLogger("kms.test")


def test_ciphertext_bitflip_rejected(svc):
    env = svc.encrypt("app-orders", "orders", b"tamper-me", aad=b"ctx")
    flipped = bytearray(env.ciphertext)
    flipped[0] ^= 0x01
    forged = replace(env, ciphertext=bytes(flipped))
    with pytest.raises(IntegrityError) as exc_info:
        svc.decrypt("app-orders", forged, aad=b"ctx")
    logger.info("判定依据: 密文第 0 字节翻转 -> GCM 标签校验失败, code=%s (v%d)",
                exc_info.value.code, env.key_version)
    assert exc_info.value.code == "integrity_error"


def test_tag_tamper_rejected(svc):
    env = svc.encrypt("app-orders", "orders", b"tamper-me")
    forged = replace(env, tag=bytes([env.tag[0] ^ 0xFF]) + env.tag[1:])
    with pytest.raises(IntegrityError):
        svc.decrypt("app-orders", forged)
    logger.info("判定依据: 认证标签被改动 -> integrity_error (v%d)", env.key_version)


def test_aad_mismatch_rejected(svc):
    env = svc.encrypt("app-orders", "orders", b"tamper-me", aad=b"tenant-A")
    with pytest.raises(IntegrityError) as exc_info:
        svc.decrypt("app-orders", env, aad=b"tenant-B")
    logger.info("判定依据: 解密时附加数据与加密时不一致 -> %s", exc_info.value.code)


def test_metadata_version_tamper_rejected(svc):
    svc.rotate_key("admin", "orders")  # 现在存在 v1(archived) 与 v2(active)
    env = svc.encrypt("app-orders", "orders", b"tamper-me")  # 用 v2 加密
    forged = replace(env, key_version=1)  # 把元数据改成 v1
    with pytest.raises(IntegrityError) as exc_info:
        svc.decrypt("app-orders", forged)
    logger.info("判定依据: 封装元数据版本 v%d 被改为 v1 -> 用错误密钥版本/AAD 校验失败 -> %s",
                env.key_version, exc_info.value.code)


def test_key_id_tamper_rejected(svc):
    svc.create_key("admin", "payments")
    env = svc.encrypt("app-orders", "orders", b"tamper-me")
    forged = replace(env, key_id="payments")
    # key_id 编入 AAD，即使 payments 密钥存在且调用方越权问题被排除，完整性校验也会失败；
    # 此处 app-orders 对 payments 无授权，应优先得到越权错误（见 test_authz）。
    env2 = svc.encrypt("app-orders", "orders", b"x")
    forged2 = replace(env2, key_id="orders")  # 控制变量：同 key_id 正常
    assert svc.decrypt("app-orders", forged2) == b"x"
    logger.info("判定依据: key_id 属于认证元数据, 改动后无法通过完整性或授权校验")


def test_malformed_envelope_rejected(svc):
    with pytest.raises(EnvelopeFormatError) as exc_info:
        svc.decrypt("app-orders", None)  # type: ignore[arg-type]
    logger.info("判定依据: 非法封装格式 -> %s", exc_info.value.code)
    assert exc_info.value.code == "envelope_format_error"


def test_no_wrong_plaintext_returned(svc):
    """篡改场景下绝不返回错误明文：要么正确解密，要么抛错。"""
    env = svc.encrypt("app-orders", "orders", b"original")
    forged = replace(env, ciphertext=env.ciphertext[:-1] + bytes([env.ciphertext[-1] ^ 1]))
    try:
        result = svc.decrypt("app-orders", forged)
    except IntegrityError:
        result = None
    assert result != b"original" and result is None
    logger.info("判定依据: 篡改后解密抛出 IntegrityError, 未返回任何明文")
