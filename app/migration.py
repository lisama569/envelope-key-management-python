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

from app.errors import EnvelopeFormatError, MigrationBatchMismatchError
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


def validate_envelope_for_migration(env: object, index: int, key_id: str) -> Envelope:
    """严格校验迁移批次中的单个元素是否为可处理的合法信封。

    类型不对、字段缺失/类型不对、结构不完整或与批次目标密钥不一致时，
    一律抛 EnvelopeFormatError（code=envelope_format_error），
    与越权（authorization_error/key_scope_error）、版本不存在（key_not_found）
    明确区分；绝不把 AttributeError/ValueError 等内部异常冒给调用方。
    """
    if not isinstance(env, Envelope):
        raise EnvelopeFormatError(
            f"migration batch item {index} is not a valid envelope: "
            f"expected Envelope, got {type(env).__name__}"
        )
    problems: list[str] = []
    if not isinstance(env.key_id, str) or not env.key_id:
        problems.append("key_id must be a non-empty string")
    elif env.key_id != key_id:
        problems.append(
            f"key_id mismatch: item belongs to {env.key_id!r}, "
            f"but batch targets {key_id!r}"
        )
    if not isinstance(env.key_version, int) or isinstance(env.key_version, bool) \
            or env.key_version < 1:
        problems.append("key_version must be a positive integer")
    for name, value, expected_len in (("iv", env.iv, 12), ("tag", env.tag, 16)):
        if not isinstance(value, bytes) or len(value) != expected_len:
            problems.append(f"{name} must be exactly {expected_len} raw bytes")
    for name in ("ciphertext", "aad"):
        value = getattr(env, name)
        if not isinstance(value, bytes):
            problems.append(f"{name} must be raw bytes")
    if problems:
        raise EnvelopeFormatError(
            f"migration batch item {index} is not a valid envelope: "
            + "; ".join(problems)
        )
    return env


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

    # ---- 退役把关所需的查询（整把密钥维度） ----

    def outstanding_count(self, key_id: str) -> int:
        """这把密钥（任一版本）上尚未迁成功（PENDING/FAILED）的密文项数量。

        退役把关按"密钥"而不是"被退役版本"判定：只要同一 key_id 的任何一个
        登记批次中还有历史数据没迁成功，该密钥的任何归档版本都不能退役。
        """
        with self._lock:
            n = 0
            for batch in self._batches.values():
                if batch.key_id != key_id:
                    continue
                for fp in batch.order:
                    item = batch.items[fp]
                    if item.status in (MigrationStatus.PENDING, MigrationStatus.FAILED):
                        n += 1
            return n

    def outstanding_summary(self, key_id: str) -> list[tuple[str, str, int, str]]:
        """返回 (batch_id, fingerprint, source_version, status) 明细。

        覆盖这把密钥所有版本、所有登记批次中的未成功项，用于在拒绝退役时
        说清是哪个批次、哪一项、卡在什么状态（以及它来自哪个版本）。
        """
        with self._lock:
            rows = []
            for batch in self._batches.values():
                if batch.key_id != key_id:
                    continue
                for fp in batch.order:
                    item = batch.items[fp]
                    if item.status in (MigrationStatus.PENDING, MigrationStatus.FAILED):
                        rows.append((batch.batch_id, fp, item.source_version,
                                     item.status.value))
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
