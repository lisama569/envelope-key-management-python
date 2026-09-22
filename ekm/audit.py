"""审计日志：仅追加的哈希链，保证密钥状态变更记录可核验。

每一行是一条规范 JSON，``entry_hash = SHA256(prev_hash || canonical_body)``，
首条记录的 prev_hash 为 ``GENESIS``。任何插入、删除、改写都会让后续链断裂，
``verify()`` 重算全链即可发现。行末同时记录自身哈希（hash 不参与自身计算）。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .errors import AuditVerificationError

GENESIS_HASH = "GENESIS"


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

    def body(self) -> dict:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "key_id": self.key_id,
            "key_version": self.key_version,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _digest(prev_hash: str, body: dict) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + _canonical(body)).hexdigest()


class AuditLog:
    """追加写 JSONL，每条记录包含前一条哈希，形成可校验链。"""

    GENESIS_HASH = GENESIS_HASH

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _last_hash_and_seq(self) -> tuple[str, int]:
        if not self.path.is_file():
            return GENESIS_HASH, 0
        seq = 0
        last_hash = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                seq = int(record["seq"])
                last_hash = record["entry_hash"]
        return last_hash, seq

    def append(self, *, action: str, actor: str, key_id: str,
               key_version: int, detail: str = "") -> AuditEntry:
        """追加一条审计记录；序号连续、哈希链接前一条。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        prev_hash, last_seq = self._last_hash_and_seq()
        entry = AuditEntry(
            seq=last_seq + 1,
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            actor=actor,
            key_id=key_id,
            key_version=int(key_version),
            detail=detail,
            prev_hash=prev_hash,
            entry_hash="",
        )
        entry_hash = _digest(prev_hash, entry.body())
        entry = AuditEntry(**entry.body(), entry_hash=entry_hash)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({**entry.body(), "entry_hash": entry.entry_hash},
                                ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    def read_all(self) -> list[AuditEntry]:
        if not self.path.is_file():
            return []
        entries: list[AuditEntry] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if "entry_hash" not in record:
                    raise AuditVerificationError(f"第 {line_no} 行缺少 entry_hash")
                stored_hash = record.pop("entry_hash")
                entries.append(AuditEntry(**record, entry_hash=stored_hash))
        return entries

    def verify(self) -> None:
        """全量重算哈希链；不一致时抛出 AuditVerificationError。"""
        entries = self.read_all()
        prev_hash = GENESIS_HASH
        expected_seq = 0
        for entry in entries:
            expected_seq += 1
            if entry.seq != expected_seq:
                raise AuditVerificationError(
                    f"审计序号不连续：期望 {expected_seq}，实际 {entry.seq}")
            if entry.prev_hash != prev_hash:
                raise AuditVerificationError(
                    f"第 {entry.seq} 条 prev_hash 断裂")
            if _digest(prev_hash, entry.body()) != entry.entry_hash:
                raise AuditVerificationError(
                    f"第 {entry.seq} 条内容与哈希不符（记录可能被改写）")
            prev_hash = entry.entry_hash
