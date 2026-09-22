"""信封加密原语：主密钥派生、DEK 封装/解封装、完整性分层校验。

完整性模型（三层，各自独立密钥/标签，篡改原因可区分）：

1. 头部标签 HAT：HMAC(hat_key, 规范头部)，保护 envelope_version/key_id/key_version
   以及 wrapped_dek（wrapped_dek 的 GCM 也以规范头部为 AAD）。
2. 附加数据标签 AAT：HMAC(aat_key, aad)，aat_key 经 HKDF 从 DEK 派生，
   因此只有先正确解封装 DEK 才能校验 AAD —— AAD 与密文分层独立。
3. 数据密文：AES-256-GCM(DEK, nonce, plaintext, aad)，标签随密文存放，
   密文/标签/nonce 被改动时 GCM 认证失败。

校验顺序固定为 HAT -> 解封装 DEK -> AAT -> 数据 GCM，对应三类可区分错误：
EKM_METADATA_TAMPERED / EKM_AAD_TAMPERED / EKM_CIPHERTEXT_TAMPERED。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import (
    AadTamperedError,
    CiphertextTamperedError,
    MalformedEnvelopeError,
    MetadataTamperedError,
)

ENVELOPE_VERSION = 1
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16

_HKDF_SALT = b"ekm-envelope-key-management-v1"
_KDF_INFO_VERSION = b"version-key"
_KDF_INFO_WRAP = b"wrap-key"
_KDF_INFO_HAT = b"hat-key"
_KDF_INFO_AAT = b"aat-key"

_REQUIRED_FIELDS = (
    "envelope_version",
    "key_id",
    "key_version",
    "iv",
    "wrapped_dek",
    "ciphertext",
    "aad",
    "hat",
    "aat",
)


@dataclass(frozen=True)
class Envelope:
    """信封加密的封装结果（JSON 可序列化）。"""

    key_id: str
    key_version: int
    envelope_version: int
    iv: str
    wrapped_dek: str
    ciphertext: str
    aad: str
    hat: str
    aat: str

    def to_dict(self) -> dict:
        return {
            "envelope_version": self.envelope_version,
            "key_id": self.key_id,
            "key_version": self.key_version,
            "iv": self.iv,
            "wrapped_dek": self.wrapped_dek,
            "ciphertext": self.ciphertext,
            "aad": self.aad,
            "hat": self.hat,
            "aat": self.aat,
        }


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value: str) -> bytes:
    if not isinstance(value, str):
        raise MalformedEnvelopeError("base64 字段不是字符串")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - 任意解码异常都归为结构损坏
        raise MalformedEnvelopeError("base64 解码失败") from exc


def _hkdf(ikm: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=_HKDF_SALT,
        info=info,
    ).derive(ikm)


def generate_master_secret() -> bytes:
    """生成新的主密钥根随机量（32 字节）。"""
    return os.urandom(KEY_SIZE)


def derive_version_key(master_secret: bytes, key_id: str, version: int) -> bytes:
    """从主密钥根派生指定版本的版本密钥（HKDF-SHA256）。"""
    info = _KDF_INFO_VERSION + b":" + key_id.encode("utf-8") + b":" + str(version).encode("ascii")
    return _hkdf(master_secret, info)


def _derive_subkey(version_key: bytes, label: bytes, key_id: str, version: int) -> bytes:
    info = label + b":" + key_id.encode("utf-8") + b":" + str(version).encode("ascii")
    return _hkdf(version_key, info)


def _canonical_header(envelope_version: int, key_id: str, key_version: int) -> bytes:
    """头部规范化编码：字段固定、键排序、无空白。"""
    return json.dumps(
        {"envelope_version": envelope_version, "key_id": key_id, "key_version": key_version},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def encrypt_blob(
    *,
    version_key: bytes,
    key_id: str,
    key_version: int,
    plaintext: bytes,
    aad: bytes,
) -> Envelope:
    """用版本密钥执行信封加密，返回带分层完整性标签的封装结构。"""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext 必须是 bytes")
    if not isinstance(aad, (bytes, bytearray)):
        raise TypeError("aad 必须是 bytes")

    wrap_key = _derive_subkey(version_key, _KDF_INFO_WRAP, key_id, key_version)
    hat_key = _derive_subkey(version_key, _KDF_INFO_HAT, key_id, key_version)
    header = _canonical_header(ENVELOPE_VERSION, key_id, key_version)

    # 1) 生成数据加密密钥 DEK 并用版本密钥封装（GCM，AAD=规范头部）
    dek = os.urandom(KEY_SIZE)
    wrap_nonce = os.urandom(NONCE_SIZE)
    wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, dek, header)
    wrapped_dek = wrap_nonce + wrapped  # nonce12 || ciphertext||tag16

    # 2) 用 DEK 加密实际数据（GCM，AAD=调用方附加数据）
    data_nonce = os.urandom(NONCE_SIZE)
    ct_blob = AESGCM(dek).encrypt(data_nonce, bytes(plaintext), bytes(aad))

    # 3) 头部标签 HAT（覆盖头部；wrapped_dek 的真实性由其自身 GCM 标签承担）
    hat = hmac.new(hat_key, header, hashlib.sha256).digest()

    # 4) 附加数据标签 AAT（密钥派生自 DEK，与头部层独立）
    aat_key = _hkdf(dek, _KDF_INFO_AAT)
    aat = hmac.new(aat_key, bytes(aad), hashlib.sha256).digest()

    return Envelope(
        key_id=key_id,
        key_version=key_version,
        envelope_version=ENVELOPE_VERSION,
        iv=_b64e(data_nonce),
        wrapped_dek=_b64e(wrapped_dek),
        ciphertext=_b64e(ct_blob),
        aad=_b64e(bytes(aad)),
        hat=_b64e(hat),
        aat=_b64e(aat),
    )


def _require_int(envelope: dict, name: str) -> int:
    value = envelope.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise MalformedEnvelopeError(f"字段 {name} 必须是整数")
    return value


def _require_str(envelope: dict, name: str) -> str:
    value = envelope.get(name)
    if not isinstance(value, str):
        raise MalformedEnvelopeError(f"字段 {name} 必须是字符串")
    return value


def decrypt_blob(
    *,
    version_key: bytes,
    envelope: dict,
    expected_aad: bytes | None = None,
) -> bytes:
    """按 头部 -> DEK 解封装 -> AAD -> 密文 的顺序分层校验并解密。

    expected_aad 非空时还要求与信封内携带的 AAD 完全一致（上下文绑定）。
    任何一层不通过都抛出对应可区分错误，绝不返回明文。
    """
    if not isinstance(envelope, dict):
        raise MalformedEnvelopeError("信封必须是 JSON 对象")
    missing = [f for f in _REQUIRED_FIELDS if f not in envelope]
    if missing:
        raise MalformedEnvelopeError(f"信封缺少字段: {','.join(missing)}")

    envelope_version = _require_int(envelope, "envelope_version")
    key_version = _require_int(envelope, "key_version")
    key_id = _require_str(envelope, "key_id")
    if envelope_version != ENVELOPE_VERSION:
        raise MalformedEnvelopeError(f"不支持的 envelope_version: {envelope_version}")

    hat = _b64d(_require_str(envelope, "hat"))
    data_nonce = _b64d(_require_str(envelope, "iv"))
    wrapped_dek = _b64d(_require_str(envelope, "wrapped_dek"))
    ct_blob = _b64d(_require_str(envelope, "ciphertext"))
    aad = _b64d(_require_str(envelope, "aad"))
    aat = _b64d(_require_str(envelope, "aat"))

    header = _canonical_header(envelope_version, key_id, key_version)

    # 第 1 层：头部完整性（key_id/key_version/envelope_version）
    hat_key = _derive_subkey(version_key, _KDF_INFO_HAT, key_id, key_version)
    expected_hat = hmac.new(hat_key, header, hashlib.sha256).digest()
    if len(hat) != len(expected_hat) or not hmac.compare_digest(hat, expected_hat):
        raise MetadataTamperedError(
            "封装元数据头部校验失败（key_id/key_version 可能被改动）",
            details={"key_id": key_id, "key_version": key_version},
        )

    # 第 2 层：解封装 DEK（wrapped_dek 或头部与封装不一致时失败）
    wrap_key = _derive_subkey(version_key, _KDF_INFO_WRAP, key_id, key_version)
    if len(wrapped_dek) < NONCE_SIZE + TAG_SIZE:
        raise MetadataTamperedError("wrapped_dek 长度异常")
    wrap_nonce, wrapped_ct = wrapped_dek[:NONCE_SIZE], wrapped_dek[NONCE_SIZE:]
    try:
        dek = AESGCM(wrap_key).decrypt(wrap_nonce, wrapped_ct, header)
    except Exception as exc:  # noqa: BLE001
        raise MetadataTamperedError(
            "DEK 解封装失败（wrapped_dek 或封装元数据被改动）",
            details={"key_id": key_id, "key_version": key_version},
        ) from exc

    # 第 3 层：附加数据完整性
    if expected_aad is not None and bytes(expected_aad) != aad:
        raise AadTamperedError("调用方提供的 AAD 与信封携带的 AAD 不一致")
    aat_key = _hkdf(dek, _KDF_INFO_AAT)
    expected_aat = hmac.new(aat_key, aad, hashlib.sha256).digest()
    if len(aat) != len(expected_aat) or not hmac.compare_digest(aat, expected_aat):
        raise AadTamperedError(
            "附加数据校验失败（aad/aat 被改动）",
            details={"key_id": key_id, "key_version": key_version},
        )

    # 第 4 层：数据密文完整性
    if len(data_nonce) != NONCE_SIZE or len(ct_blob) < TAG_SIZE:
        raise CiphertextTamperedError("iv/ciphertext 长度异常")
    try:
        plaintext = AESGCM(dek).decrypt(data_nonce, ct_blob, aad)
    except Exception as exc:  # noqa: BLE001
        raise CiphertextTamperedError(
            "密文认证失败（ciphertext/iv/标签被改动）",
            details={"key_id": key_id, "key_version": key_version},
        ) from exc

    return plaintext
