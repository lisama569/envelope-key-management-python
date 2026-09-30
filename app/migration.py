"""历史密文迁移的批次与逐项进度存储（线程安全，可快照持久化）。

幂等模型：
- 批次由调用方提供的 batch_id 标识；每个批次绑定一个 key_id 和一组密文指纹。
- 密文指纹 = 信封全部字段（含版本、IV、密文、标签、AAD）的规范哈希，
  因此"同一批反复提交"能被识别，重复迁移/漏迁都不会发生。
- 每个项有 PENDING / MIGRATED / ALREADY_CURRENT / FAILED 状态，
  FAILED/PENDING 都算"未成功"，可被同批次重试继续推进。
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from app.errors import MigrationBatchMismatchError
from app.models import Envelope, MigrationStatus


def envelope_to_dict(env: Envelope) -> dict:
    return {
        "key_id": env.key_id,
        "key_version": env.key_version,
        "iv_b64": base64.b64encode(env.iv).decode(),
        "ciphertext_b64": base64.b64encode(env.ciphertext).decode(),
        "tag_b64": base64.b64encode(env.tag).decode(),
        "aad_b64": base64.b64encode(env.aad).decode(),
    }


def dict_to_envelope(d: dict) -> Envelope:
    return Envelope(
        key_id=d["key_id"],
        key_version=int(d["key_version"]),
        iv=base64.b64decode(d["iv_b64"]),
        ciphertext=base64.b64decode(d["ciphertext_b64"]),
        tag=base64.b64decode(d["tag_b64"]),
        aad=base64.b64decode(d.get("aad_b64", "")),
    )


def envelope_fingerprint(env: Envelope) -> str:
    """信封全部字段的规范 SHA-256 指纹；任一字节不同即为不同项。"""
    h = hashlib.sha256()
    kid = env.key_id.encode("utf-8")
    h.update(len(kid).to_bytes(2, "big"))
    h.update(kid)
    h.update(env.key_version.to_bytes(8, "big", signed=False))
    for part in (env.iv, env.ciphertext, env.tag, env.aad):
        h.update(len(part).to_bytes(4, "big"))
        h.update(part)
    return h.hexdigest()


@dataclass
class _Item:
    index: int
    fingerprint: str
    source: Envelope
    source_version: int
    status: MigrationStatus = MigrationStatus.PENDING
    target_version: Optional[int] = None
    target: Optional[Envelope] = None
    error: Optional[str] = None
    attempts: int = 0


@dataclass
class _Batch:
    batch_id: str
    key_id: str
    order: list[str] = field(default_factory=list)  # 首次提交的指纹顺序
    items: dict[str, _Item] = field(default_factory=dict)
    created_at: float = 0.0


class MigrationStore:
    """登记迁移批次并持久化每项的迁移进度。"""

    def __init__(self, snapshot: dict | None = None) -> None:
        self._lock = threading.RLock()
        self._batches: dict[str, _Batch] = {}
        if snapshot:
            self.restore(snapshot)

    # ---- 批次登记 ----

    def register_or_get(self, batch_id: str, key_id: str,
                        envelopes: list[Envelope]) -> tuple[_Batch, bool]:
        """登记新批次或取回已登记批次。

        重复提交时按指纹集合校验一致性；集合不同则拒绝（防止串号/漏项）。
        返回 (批次, 是否新登记)。
        """
        fingerprints = [envelope_fingerprint(e) for e in envelopes]
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                batch = _Batch(batch_id=batch_id, key_id=key_id, created_at=time.time())
                for idx, (fp, env) in enumerate(zip(fingerprints, envelopes)):
                    batch.order.append(fp)
                    batch.items[fp] = _Item(
                        index=idx, fingerprint=fp, source=env,
                        source_version=env.key_version,
                    )
                self._batches[batch_id] = batch
                return batch, True
            if batch.key_id != key_id or set(batch.order) != set(fingerprints):
                raise MigrationBatchMismatchError(
                    f"batch {batch_id!r} resubmitted with a different envelope set "
                    f"(registered key={batch.key_id}, items={len(batch.order)})"
                )
            return batch, False

    def get_batch(self, batch_id: str) -> Optional[_Batch]:
        with self._lock:
            return self._batches.get(batch_id)

    # ---- 逐项进度 ----

    def record_attempt(self, item: _Item) -> None:
        with self._lock:
            item.attempts += 1

    def mark_migrated(self, item: _Item, target_version: int,
                      target_envelope: Envelope) -> None:
        with self._lock:
            # CAS：只有仍未成功的项可以落到 MIGRATED，避免重复迁移覆盖
            if item.status in (MigrationStatus.MIGRATED, MigrationStatus.ALREADY_CURRENT):
                return
            item.status = MigrationStatus.MIGRATED
            item.target_version = target_version
            item.target = target_envelope
            item.error = None

    def mark_already_current(self, item: _Item, active_version: int) -> None:
        with self._lock:
            if item.status in (MigrationStatus.MIGRATED, MigrationStatus.ALREADY_CURRENT):
                return
            item.status = MigrationStatus.ALREADY_CURRENT
            item.target_version = active_version
            item.target = item.source
            item.error = None

    def mark_failed(self, item: _Item, error: str) -> None:
        with self._lock:
            item.status = MigrationStatus.FAILED
            item.error = error

    # ---- 退役把关所需的查询 ----

    def outstanding_count(self, key_id: str, version: int | None = None) -> int:
        """尚未迁完（PENDING/FAILED）的密文项数量。

        version 为 None 时统计整把密钥（所有来源版本），否则只统计该版本名下。
        """
        return len(self.outstanding_summary(key_id, version))

    def outstanding_summary(
        self, key_id: str, version: int | None = None
    ) -> list[tuple[str, str, str, int]]:
        """返回 (batch_id, fingerprint, status, source_version) 明细。

        退役把关以整把密钥为粒度（version=None）：只要这把密钥还有任何
        没迁成功的历史数据——不管它属于哪个版本、哪个批次——都逐条列出，
        用于说清退役被拦的原因。
        """
        with self._lock:
            rows = []
            for batch in self._batches.values():
                if batch.key_id != key_id:
                    continue
                for fp in batch.order:
                    item = batch.items[fp]
                    if version is not None and item.source_version != version:
                        continue
                    if item.status in (
                        MigrationStatus.PENDING, MigrationStatus.FAILED,
                    ):
                        rows.append((batch.batch_id, fp, item.status.value,
                                     item.source_version))
            return rows

    # ---- 快照 ----

    def snapshot(self) -> dict:
        with self._lock:
            out = {}
            for bid, batch in self._batches.items():
                items = {}
                for fp in batch.order:
                    it = batch.items[fp]
                    items[fp] = {
                        "index": it.index,
                        "source_version": it.source_version,
                        "status": it.status.value,
                        "target_version": it.target_version,
                        "attempts": it.attempts,
                        "error": it.error,
                        "source": envelope_to_dict(it.source),
                        "target": envelope_to_dict(it.target) if it.target else None,
                    }
                out[bid] = {
                    "key_id": batch.key_id,
                    "order": list(batch.order),
                    "created_at": batch.created_at,
                    "items": items,
                }
            return {"batches": out}

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            self._batches = {}
            for bid, data in snapshot.get("batches", {}).items():
                batch = _Batch(
                    batch_id=bid, key_id=data["key_id"],
                    order=list(data["order"]), created_at=float(data.get("created_at", 0.0)),
                )
                for fp in batch.order:
                    d = data["items"][fp]
                    it = _Item(
                        index=int(d["index"]),
                        fingerprint=fp,
                        source=dict_to_envelope(d["source"]),
                        source_version=int(d["source_version"]),
                        status=MigrationStatus(d["status"]),
                        target_version=d.get("target_version"),
                        target=dict_to_envelope(d["target"]) if d.get("target") else None,
                        error=d.get("error"),
                        attempts=int(d.get("attempts", 0)),
                    )
                    batch.items[fp] = it
                self._batches[bid] = batch
