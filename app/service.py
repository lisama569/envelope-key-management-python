"""密钥管理服务门面：组合存储、加密、授权与审计。"""

from __future__ import annotations

from app.audit import AuditLog
from app.authz import Authorizer
from app.crypto import EnvelopeCipher
from app.errors import (
    EnvelopeFormatError,
    KeyManagementError,
    KeyNotFoundError,
    NoActiveKeyError,
)
from app.keystore import LocalKeyStore
from app.models import Envelope


class KeyManagementService:
    """对外暴露 create/rotate/encrypt/decrypt，所有状态变更均审计。"""

    def __init__(
        self,
        keystore: LocalKeyStore | None = None,
        cipher: EnvelopeCipher | None = None,
        authorizer: Authorizer | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self._keystore = keystore or LocalKeyStore()
        self._cipher = cipher or EnvelopeCipher()
        self._authorizer = authorizer or Authorizer()
        self._audit = audit or AuditLog()

    @property
    def audit(self) -> AuditLog:
        return self._audit

    @property
    def authorizer(self) -> Authorizer:
        return self._authorizer

    @property
    def keystore(self) -> LocalKeyStore:
        return self._keystore

    def create_key(self, caller: str, key_id: str) -> int:
        self._authorizer.check(caller, key_id, "create")
        try:
            kv = self._keystore.create_key(key_id)
        except ValueError as exc:
            raise KeyManagementConflictError(str(exc)) from exc
        self._audit.append(caller, "create_key", key_id,
                           f"version={kv.version} status=active")
        return kv.version

    def rotate_key(self, caller: str, key_id: str) -> int:
        self._authorizer.check(caller, key_id, "rotate")
        try:
            kv = self._keystore.rotate(key_id)
        except KeyError as exc:
            raise KeyNotFoundError(f"unknown key: {key_id}") from exc
        self._audit.append(caller, "rotate_key", key_id,
                           f"new_active_version={kv.version} previous_archived")
        return kv.version

    def encrypt(self, caller: str, key_id: str, plaintext: bytes, aad: bytes = b"") -> Envelope:
        self._authorizer.check(caller, key_id, "encrypt")
        kv = self._keystore.get_active(key_id)
        if kv is None:
            raise NoActiveKeyError(f"no active key version for {key_id!r}")
        # 在取到的版本上完成加密：即使此刻发生轮换，该版本已被归档保留，
        # 密文仍可通过信封中的 (key_id, version) 定位并解密。
        return self._cipher.encrypt(kv, plaintext, aad)

    def decrypt(self, caller: str, envelope: Envelope, aad: bytes = b"") -> bytes:
        if not isinstance(envelope, Envelope) or not envelope.key_id or envelope.key_version < 1:
            raise EnvelopeFormatError("malformed envelope")
        self._authorizer.check(caller, envelope.key_id, "decrypt")
        kv = self._keystore.get_version(envelope.key_id, envelope.key_version)
        if kv is None:
            raise KeyNotFoundError(
                f"key version not found: {envelope.key_id} v{envelope.key_version}"
            )
        return self._cipher.decrypt(kv, envelope, aad)


class KeyManagementConflictError(KeyManagementError):
    """密钥已存在等状态冲突。"""

    code = "key_conflict"
