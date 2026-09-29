"""审计日志：追加式、哈希链可核验（线程安全，可选持久化）。"""

from __future__ import annotations

import hashlib
import threading
import time

from app.models import AuditRecord
from app.persistence import atomic_write_json, ensure_state_dir, read_json, state_path

_GENESIS = "0" * 64
_AUDIT_FILE = "audit.json"


def _hash_record(seq: int, timestamp: float, caller: str, action: str,
                 key_id: str, detail: str, prev_hash: str) -> str:
    payload = f"{seq}|{timestamp!r}|{caller}|{action}|{key_id}|{detail}|{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    """内存审计日志并可落盘；每条记录包含前一条记录的哈希，形成可核验链。

    锁内完成序号分配与追加，保证并发下链式哈希仍自洽。
    传入 state_dir 时记录持久化：重启后从同一目录恢复，
    新记录的 prev_hash 接在恢复出的最后一条之后，链不断裂。
    """

    def __init__(self, state_dir: str | None = None) -> None:
        self._lock = threading.Lock()
        self._state_dir = ensure_state_dir(state_dir)
        self._path = state_path(self._state_dir, _AUDIT_FILE)
        self._records: list[AuditRecord] = []
        with self._lock:
            self._load()

    def _load(self) -> None:
        data = read_json(self._path) if self._path else None
        if not data:
            return
        for item in data:
            self._records.append(AuditRecord(
                seq=item["seq"],
                timestamp=item["timestamp"],
                caller=item["caller"],
                action=item["action"],
                key_id=item["key_id"],
                detail=item["detail"],
                prev_hash=item["prev_hash"],
                record_hash=item["record_hash"],
            ))

    def _save(self) -> None:
        if self._path is None:
            return
        atomic_write_json(self._path, [r.__dict__ for r in self._records])

    def append(self, caller: str, action: str, key_id: str, detail: str) -> AuditRecord:
        with self._lock:
            seq = len(self._records) + 1
            prev_hash = self._records[-1].record_hash if self._records else _GENESIS
            ts = time.time()
            record = AuditRecord(
                seq=seq,
                timestamp=ts,
                caller=caller,
                action=action,
                key_id=key_id,
                detail=detail,
                prev_hash=prev_hash,
                record_hash=_hash_record(seq, ts, caller, action, key_id, detail, prev_hash),
            )
            self._records.append(record)
            self._save()
            return record

    def verify(self) -> bool:
        """校验整条哈希链是否完整（无插入、删除或篡改）。"""
        with self._lock:
            prev_hash = _GENESIS
            for expected_seq, rec in enumerate(self._records, start=1):
                if rec.seq != expected_seq or rec.prev_hash != prev_hash:
                    return False
                if rec.record_hash != _hash_record(
                    rec.seq, rec.timestamp, rec.caller, rec.action,
                    rec.key_id, rec.detail, rec.prev_hash,
                ):
                    return False
                prev_hash = rec.record_hash
            return True

    def records(self) -> list[AuditRecord]:
        with self._lock:
            return list(self._records)
