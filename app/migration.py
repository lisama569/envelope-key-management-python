"""历史密文迁移登记表：幂等、可重试、崩溃可恢复。

登记以"原始密文指纹"为键：同一密文无论被提交多少次、来自多少个批次，
在表里只有一条记录，因此反复提交不会重复迁、也不会把已迁好的弄坏。
状态机见 models.MigrationStatus；所有状态变更即时落盘，
进程崩溃时残留的 PROCESSING 会在重启加载时回退为 PENDING，可接着重试。
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time

from app.models import Envelope, MigrationRecord, MigrationStatus
from app.persistence import atomic_write_json, ensure_state_dir, read_json, state_path

_MIGRATIONS_FILE = "migrations.json"

_TERMINAL = frozenset({MigrationStatus.MIGRATED, MigrationStatus.ALREADY_CURRENT})
_UNFINISHED = frozenset(
    {MigrationStatus.PENDING, MigrationStatus.PROCESSING, MigrationStatus.FAILED}
)


# ------------------------------------------------------------------ 信封编解码
def envelope_to_dict(env: Envelope) -> dict:
    return {
        "key_id": env.key_id,
        "key_version": env.key_version,
        "iv_b64": base64.b64encode(env.iv).decode(),
        "ciphertext_b64": base64.b64encode(env.ciphertext).decode(),
        "tag_b64": base64.b64encode(env.tag).decode(),
        "aad_b64": base64.b64encode(env.aad).decode(),
    }


def envelope_from_dict(d: dict) -> Envelope:
    return Envelope(
        key_id=d["key_id"],
        key_version=d["key_version"],
        iv=base64.b64decode(d["iv_b64"]),
        ciphertext=base64.b64decode(d["ciphertext_b64"]),
        tag=base64.b64decode(d["tag_b64"]),
        aad=base64.b64decode(d.get("aad_b64", "")),
    )


def envelope_fingerprint(env: Envelope) -> str:
    """对完整信封（含版本、IV、密文、标签、AAD）取规范化 SHA-256 指纹。"""
    canonical = json.dumps(envelope_to_dict(env), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class MigrationRegistry:
    """指纹 -> MigrationRecord 的线程安全登记表，可选 JSON 持久化。"""

    def __init__(self, state_dir: str | None = None) -> None:
        self._lock = threading.RLock()
        self._state_dir = ensure_state_dir(state_dir)
        self._path = state_path(self._state_dir, _MIGRATIONS_FILE)
        self._records: dict[str, MigrationRecord] = {}
        with self._lock:
            self._load()

    # ------------------------------------------------------------------ 持久化
    def _load(self) -> None:
        data = read_json(self._path) if self._path else None
        if not data:
            return
        for fp, item in data.items():
            status = MigrationStatus(item["status"])
            # 崩溃恢复：上次正在处理中途断掉，回退为 PENDING 等待重试
            if status is MigrationStatus.PROCESSING:
                status = MigrationStatus.PENDING
            result = envelope_from_dict(item["result"]) if item.get("result") else None
            self._records[fp] = MigrationRecord(
                fingerprint=fp,
                key_id=item["key_id"],
                source_version=item["source_version"],
                status=status,
                target_version=item.get("target_version"),
                result=result,
                attempts=item.get("attempts", 0),
                last_error=item.get("last_error"),
                updated_at=item.get("updated_at", 0.0),
            )

    def _save(self) -> None:
        if self._path is None:
            return
        payload = {
            fp: {
                "key_id": rec.key_id,
                "source_version": rec.source_version,
                "status": rec.status.value,
                "target_version": rec.target_version,
                "result": envelope_to_dict(rec.result) if rec.result else None,
                "attempts": rec.attempts,
                "last_error": rec.last_error,
                "updated_at": rec.updated_at,
            }
            for fp, rec in self._records.items()
        }
        atomic_write_json(self._path, payload)

    def _put(self, rec: MigrationRecord) -> MigrationRecord:
        saved = MigrationRecord(
            fingerprint=rec.fingerprint, key_id=rec.key_id,
            source_version=rec.source_version, status=rec.status,
            target_version=rec.target_version, result=rec.result,
            attempts=rec.attempts, last_error=rec.last_error,
            updated_at=time.time(),
        )
        self._records[rec.fingerprint] = saved
        self._save()
        return saved

    # ------------------------------------------------------------------ 查询
    def get(self, fp: str) -> MigrationRecord | None:
        with self._lock:
            return self._records.get(fp)

    def unfinished_count_for_source(self, key_id: str, version: int) -> int:
        """统计某 (key_id, 源版本) 下仍未成功迁移的登记项数量。"""
        with self._lock:
            return sum(
                1 for rec in self._records.values()
                if rec.key_id == key_id and rec.source_version == version
                and rec.status in _UNFINISHED
            )

    def unfinished_count_for_key(self, key_id: str) -> int:
        """统计该 key 下任意来源仍未成功迁移的项（含上次失败遗留）。"""
        with self._lock:
            return sum(
                1 for rec in self._records.values()
                if rec.key_id == key_id and rec.status in _UNFINISHED
            )

    # ------------------------------------------------------------------ 状态转移
    def begin(self, fp: str, key_id: str, source_version: int) -> MigrationRecord:
        """声明开始处理一个指纹：

        - 不存在：建为 PROCESSING（attempts=1）并落盘；
        - 已成功（MIGRATED/ALREADY_CURRENT）：原样返回，调用方据此跳过；
        - PENDING/FAILED/崩溃残留：转为 PROCESSING，attempts +1。
        """
        with self._lock:
            rec = self._records.get(fp)
            if rec is None:
                rec = MigrationRecord(
                    fingerprint=fp, key_id=key_id,
                    source_version=source_version,
                    status=MigrationStatus.PROCESSING, attempts=1,
                )
            elif rec.status in _TERMINAL:
                return rec
            else:
                rec = MigrationRecord(
                    fingerprint=fp, key_id=rec.key_id,
                    source_version=rec.source_version,
                    status=MigrationStatus.PROCESSING,
                    target_version=None, result=None,
                    attempts=rec.attempts + 1,
                    last_error=rec.last_error,
                )
            return self._put(rec)

    def complete(self, fp: str, target_version: int, result: Envelope) -> MigrationRecord:
        with self._lock:
            rec = self._records[fp]
            return self._put(MigrationRecord(
                fingerprint=fp, key_id=rec.key_id,
                source_version=rec.source_version,
                status=MigrationStatus.MIGRATED,
                target_version=target_version, result=result,
                attempts=rec.attempts, last_error=None,
            ))

    def fail(self, fp: str, error: str) -> MigrationRecord:
        with self._lock:
            rec = self._records[fp]
            return self._put(MigrationRecord(
                fingerprint=fp, key_id=rec.key_id,
                source_version=rec.source_version,
                status=MigrationStatus.FAILED,
                target_version=None, result=None,
                attempts=rec.attempts, last_error=error,
            ))

    def mark_already_current(self, fp: str, key_id: str, version: int,
                             result: Envelope) -> MigrationRecord:
        """提交时本就处于当前版本：幂等记为 ALREADY_CURRENT，不做重加密。"""
        with self._lock:
            existing = self._records.get(fp)
            if existing is not None and existing.status in _TERMINAL:
                return existing
            rec = MigrationRecord(
                fingerprint=fp, key_id=key_id, source_version=version,
                status=MigrationStatus.ALREADY_CURRENT,
                target_version=version, result=result,
                attempts=0 if existing is None else existing.attempts,
            )
            return self._put(rec)
