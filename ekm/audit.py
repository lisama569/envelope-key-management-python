"""审计日志：仅追加的哈希链，保证密钥状态变更记录可核验。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    timestamp: str
    action: str
    actor: str
    key_id: str
    key_version: int
    detail: str
    prev_hash: str
    entry_hash: str


class AuditLog:
    """追加写 JSONL，每条记录包含前一条哈希，形成可校验链。"""

    GENESIS_HASH = "GENESIS"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, *, action: str, actor: str, key_id: str,
               key_version: int, detail: str = "") -> AuditEntry:
        raise NotImplementedError

    def read_all(self) -> list[AuditEntry]:
        raise NotImplementedError

    def verify(self) -> None:
        """全量重算哈希链；不一致时抛出 AuditVerificationError。"""
        raise NotImplementedError
