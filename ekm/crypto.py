"""信封加密原语：主密钥派生、DEK 封装/解封装、完整性分层校验。"""

from __future__ import annotations

from dataclasses import dataclass

ENVELOPE_VERSION = 1
NONCE_SIZE = 12


@dataclass(frozen=True)
class Envelope:
    """信封加密的封装结果（JSON 可序列化）。"""

    key_id: str
    key_version: int
    envelope_version: int
    iv: str          # base64 GCM nonce
    wrapped_dek: str  # base64 被主密钥加密的 DEK
    ciphertext: str   # base64 DEK 加密的数据
    aad: str          # 附加数据原文
    hat: str          # base64 头部 MAC（不含 aad/ciphertext）
    aat: str          # base64 AAD 的 MAC（密钥派生自 DEK）


def generate_master_secret() -> bytes:
    """生成新的主密钥根随机量。"""
    raise NotImplementedError


def derive_version_key(master_secret: bytes, key_id: str, version: int) -> bytes:
    """从主密钥根派生指定版本的版本密钥（HKDF）。"""
    raise NotImplementedError


def encrypt_blob(
    *,
    version_key: bytes,
    key_id: str,
    key_version: int,
    plaintext: bytes,
    aad: bytes,
) -> Envelope:
    """用版本密钥执行信封加密，返回带分层完整性标签的封装结构。"""
    raise NotImplementedError


def decrypt_blob(*, version_key: bytes, envelope: dict) -> bytes:
    """按 头部 -> AAD -> 密文 的顺序分层校验并解密，篡改时抛出可区分错误。"""
    raise NotImplementedError
