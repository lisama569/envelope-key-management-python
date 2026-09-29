"""本地密钥存储：模拟密钥的托管、归档与退役（线程安全，可选持久化）。"""

from __future__ import annotations

import base64
import os
import threading
import time

from app.models import KeyStatus, KeyVersion
from app.persistence import atomic_write_json, ensure_state_dir, read_json, state_path

_KEY_BYTES = 32  # AES-256
_STORE_FILE = "keys.json"


class LocalKeyStore:
    """以本地结构托管密钥版本；任一时刻每个 key_id 只有一个 ACTIVE 版本。

    生命周期：ACTIVE（可加解密）→ ARCHIVED（仅可解密）→ RETIRED（不可解密）。

    轮换在锁内原子完成：旧版本先归档、新版本再置为 ACTIVE，
    因此不存在"无可用版本"的窗口；轮换前已取到旧版本的加密请求
    仍会用旧版本完成加密，而旧版本已被归档保留，密文仍可解密。

    退役是显式动作（retire）：只允许把 ARCHIVED 版本置为 RETIRED，
    ACTIVE 版本不得直接退役。传入 state_dir 时，全部状态变更落盘，
    进程重启后用同一目录构造即可恢复。
    """

    def __init__(self, state_dir: str | None = None) -> None:
        self._lock = threading.RLock()
        self._state_dir = ensure_state_dir(state_dir)
        self._path = state_path(self._state_dir, _STORE_FILE)
        self._versions: dict[str, dict[int, KeyVersion]] = {}
        with self._lock:
            self._load()

    # ------------------------------------------------------------------ 持久化
    def _load(self) -> None:
        data = read_json(self._path) if self._path else None
        if not data:
            return
        for key_id, items in data.items():
            bucket: dict[int, KeyVersion] = {}
            for item in items:
                bucket[item["version"]] = KeyVersion(
                    key_id=item["key_id"],
                    version=item["version"],
                    status=KeyStatus(item["status"]),
                    material=base64.b64decode(item["material_b64"]),
                    created_at=item["created_at"],
                )
            self._versions[key_id] = bucket

    def _save(self) -> None:
        if self._path is None:
            return
        payload = {
            key_id: [
                {
                    "key_id": kv.key_id,
                    "version": kv.version,
                    "status": kv.status.value,
                    "material_b64": base64.b64encode(kv.material).decode(),
                    "created_at": kv.created_at,
                }
                for v in sorted(bucket)
                for kv in (bucket[v],)
            ]
            for key_id, bucket in self._versions.items()
        }
        atomic_write_json(self._path, payload)

    # ------------------------------------------------------------------ 操作
    def create_key(self, key_id: str) -> KeyVersion:
        with self._lock:
            versions = self._versions.setdefault(key_id, {})
            if versions:
                raise ValueError(f"key already exists: {key_id}")
            kv = KeyVersion(
                key_id=key_id,
                version=1,
                status=KeyStatus.ACTIVE,
                material=os.urandom(_KEY_BYTES),
                created_at=time.time(),
            )
            versions[1] = kv
            self._save()
            return kv

    def rotate(self, key_id: str) -> KeyVersion:
        with self._lock:
            versions = self._versions.get(key_id)
            if not versions:
                raise KeyError(f"unknown key: {key_id}")
            new_version = max(versions) + 1
            # 归档当前 ACTIVE 版本（RETIRED 版本保持退役，不参与轮换）
            for v, kv in list(versions.items()):
                if kv.status is KeyStatus.ACTIVE:
                    versions[v] = KeyVersion(
                        key_id=kv.key_id,
                        version=kv.version,
                        status=KeyStatus.ARCHIVED,
                        material=kv.material,
                        created_at=kv.created_at,
                    )
            kv = KeyVersion(
                key_id=key_id,
                version=new_version,
                status=KeyStatus.ACTIVE,
                material=os.urandom(_KEY_BYTES),
                created_at=time.time(),
            )
            versions[new_version] = kv
            self._save()
            return kv

    def retire(self, key_id: str, version: int) -> KeyVersion:
        """把一个 ARCHIVED 版本显式标记为 RETIRED。

        - 密钥/版本不存在：KeyError；
        - 目标仍是 ACTIVE：ValueError（必须先轮换再退役）；
        - 已是 RETIRED：幂等返回，不报错、不重复落盘。
        """
        with self._lock:
            versions = self._versions.get(key_id)
            if not versions or version not in versions:
                raise KeyError(f"unknown key version: {key_id} v{version}")
            kv = versions[version]
            if kv.status is KeyStatus.RETIRED:
                return kv
            if kv.status is KeyStatus.ACTIVE:
                raise ValueError(
                    f"cannot retire active version: {key_id} v{version}; rotate first"
                )
            retired = KeyVersion(
                key_id=kv.key_id,
                version=kv.version,
                status=KeyStatus.RETIRED,
                material=kv.material,
                created_at=kv.created_at,
            )
            versions[version] = retired
            self._save()
            return retired

    def get_active(self, key_id: str) -> KeyVersion | None:
        with self._lock:
            for kv in self._versions.get(key_id, {}).values():
                if kv.status is KeyStatus.ACTIVE:
                    return kv
            return None

    def get_version(self, key_id: str, version: int) -> KeyVersion | None:
        with self._lock:
            return self._versions.get(key_id, {}).get(version)

    def list_versions(self, key_id: str) -> list[KeyVersion]:
        with self._lock:
            return [self._versions[key_id][v] for v in sorted(self._versions.get(key_id, {}))]
