"""本地密钥存储：模拟密钥的托管、归档与退役（线程安全，可快照持久化）。"""

from __future__ import annotations

import base64
import os
import threading
import time

from app.models import KeyStatus, KeyVersion

_KEY_BYTES = 32  # AES-256


class LocalKeyStore:
    """以本地内存结构托管密钥版本；任一时刻每个 key_id 只有一个 ACTIVE 版本。

    轮换在锁内原子完成：旧版本先归档、新版本再置为 ACTIVE，
    因此不存在"无可用版本"的窗口；轮换前已取到旧版本的加密请求
    仍会用旧版本完成加密，而旧版本已被归档保留，密文仍可解密。
    """

    def __init__(self, snapshot: dict | None = None) -> None:
        self._lock = threading.RLock()
        self._versions: dict[str, dict[int, KeyVersion]] = {}
        if snapshot:
            self.restore(snapshot)

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
            return kv

    def rotate(self, key_id: str) -> KeyVersion:
        with self._lock:
            versions = self._versions.get(key_id)
            if not versions:
                raise KeyError(f"unknown key: {key_id}")
            new_version = max(versions) + 1
            # 归档当前 ACTIVE 版本
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
            return kv

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

    def retire(self, key_id: str, version: int) -> KeyVersion:
        """把一个非 ACTIVE 版本标记为 RETIRED；重复退役同一版本是幂等的。"""
        with self._lock:
            versions = self._versions.get(key_id)
            if not versions or version not in versions:
                raise KeyError(f"unknown key version: {key_id} v{version}")
            kv = versions[version]
            if kv.status is KeyStatus.ACTIVE:
                raise ValueError(f"cannot retire active version: {key_id} v{version}")
            if kv.status is KeyStatus.RETIRED:
                return kv
            retired = KeyVersion(
                key_id=kv.key_id,
                version=kv.version,
                status=KeyStatus.RETIRED,
                material=kv.material,
                created_at=kv.created_at,
            )
            versions[version] = retired
            return retired

    def snapshot(self) -> dict:
        """导出全部版本（含密钥材料，base64），供重启后恢复。"""
        with self._lock:
            out: dict[str, dict[str, dict]] = {}
            for key_id, versions in self._versions.items():
                out[key_id] = {
                    str(v): {
                        "status": kv.status.value,
                        "material_b64": base64.b64encode(kv.material).decode(),
                        "created_at": kv.created_at,
                    }
                    for v, kv in versions.items()
                }
            return {"keys": out}

    def restore(self, snapshot: dict) -> None:
        """从 snapshot() 产生的结构恢复；仅在构造期调用。"""
        with self._lock:
            self._versions = {}
            for key_id, versions in snapshot.get("keys", {}).items():
                restored: dict[int, KeyVersion] = {}
                for ver, data in versions.items():
                    v = int(ver)
                    restored[v] = KeyVersion(
                        key_id=key_id,
                        version=v,
                        status=KeyStatus(data["status"]),
                        material=base64.b64decode(data["material_b64"]),
                        created_at=float(data.get("created_at", 0.0)),
                    )
                self._versions[key_id] = restored
