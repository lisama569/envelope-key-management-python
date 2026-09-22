"""密钥管理服务：主密钥创建、轮换、版本归档、信封加解密、审计。"""

from __future__ import annotations

import threading
from pathlib import Path

from .audit import AuditLog
from .storage import LocalKeyStore


class KeyManagementService:
    """线程安全的本地信封密钥管理服务。"""

    def __init__(self, storage_dir: str | Path = "data/ekm") -> None:
        self._lock = threading.RLock()
        self.store = LocalKeyStore(Path(storage_dir) / "keys.json")
        self.audit = AuditLog(Path(storage_dir) / "audit.jsonl")
        self._records: dict = {}

    def create_key(self, *, actor: str | None, key_id: str) -> dict:
        raise NotImplementedError

    def rotate_key(self, *, actor: str | None, key_id: str,
                   idempotency_key: str | None = None) -> dict:
        raise NotImplementedError

    def get_key_status(self, *, actor: str | None, key_id: str) -> dict:
        raise NotImplementedError

    def encrypt(self, *, actor: str | None, key_id: str,
                plaintext: bytes, aad: bytes = b"") -> dict:
        raise NotImplementedError

    def decrypt(self, *, actor: str | None, envelope: dict,
                expected_aad: bytes | None = None) -> bytes:
        raise NotImplementedError
