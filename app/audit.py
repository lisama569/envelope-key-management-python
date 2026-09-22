"""审计日志：追加式、哈希链可核验。"""

from __future__ import annotations

import hashlib
import threading
import time

from app.models import AuditRecord

_GENESIS = "0" * 64


def _hash_record(seq: int, timestamp: float, caller: str, action: str,
                 key_id: str, detail: str, prev_hash: str) -> str:
    payload = f"{seq}|{timestamp!r}|{caller}|{action}|{key_id}|{detail}|{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    """内存审计日志；每条记录包含前一条记录的哈希，形成可核验链。

    锁内完成序号分配与追加，保证并发下链式哈希仍自洽。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[AuditRecord] = []

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
