"""信封加密与完整性校验（AES-256-GCM）。"""

from __future__ import annotations

import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.errors import IntegrityError
from app.models import Envelope, KeyVersion

_IV_BYTES = 12
_TAG_BYTES = 16


def _build_aad(key_id: str, key_version: int, aad: bytes) -> bytes:
    """把封装元数据（key_id、版本）与调用方附加数据一起编入 AEAD 的认证数据。

    这样 key_id/版本/aad 任一被改动都会导致 GCM 标签校验失败。
    """
    kid = key_id.encode("utf-8")
    return (
        struct.pack(">H", len(kid))
        + kid
        + struct.pack(">I", key_version)
        + struct.pack(">I", len(aad))
        + aad
    )


class EnvelopeCipher:
    """用密钥版本材料做 AEAD 加解密；AAD 绑定封装元数据与调用方附加数据。"""

    def encrypt(self, key: KeyVersion, plaintext: bytes, aad: bytes = b"") -> Envelope:
        iv = os.urandom(_IV_BYTES)
        full_aad = _build_aad(key.key_id, key.version, aad)
        ct_and_tag = AESGCM(key.material).encrypt(iv, plaintext, full_aad)
        return Envelope(
            key_id=key.key_id,
            key_version=key.version,
            iv=iv,
            ciphertext=ct_and_tag[:-_TAG_BYTES],
            tag=ct_and_tag[-_TAG_BYTES:],
            aad=aad,
        )

    def decrypt(self, key: KeyVersion, envelope: Envelope, aad: bytes = b"") -> bytes:
        # 解密时以调用方传入的 aad（若提供）为准，否则用信封内携带的 aad
        effective_aad = aad if aad else envelope.aad
        full_aad = _build_aad(envelope.key_id, envelope.key_version, effective_aad)
        try:
            return AESGCM(key.material).decrypt(
                envelope.iv, envelope.ciphertext + envelope.tag, full_aad
            )
        except InvalidTag as exc:
            raise IntegrityError(
                f"integrity check failed for key={envelope.key_id} "
                f"version={envelope.key_version}"
            ) from exc
