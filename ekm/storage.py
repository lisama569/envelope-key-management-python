"""本地持久化：模拟主密钥的托管与归档（原子写 JSON）。

文件形态：一个 ``keys.json``，结构为
``{key_id: {master_secrets: {"1": b64, ...}, current_version: 3, created_at: iso}}``。

- 任一版本的主密钥根一旦生成即不可变，按版本号归档保存；
- ``current_version`` 指向当前用于新加密的唯一版本；
- 历史版本永久保留用于解密历史密文（本服务不做物理销毁）；
- 写入采用 临时文件 + fsync + 原子替换，避免半写文件。
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class KeyRecord:
    """一个逻辑主密钥的全部版本状态。"""

    key_id: str
    current_version: int = 0
    created_at: str = ""
    # version -> 主密钥根（bytes）；该版本一经写入永不改变
    master_secrets: dict[int, bytes] = field(default_factory=dict)

    def versions(self) -> list[int]:
        """已归档（含当前）版本号，升序。"""
        return sorted(self.master_secrets)

    def secret_for(self, version: int) -> Optional[bytes]:
        return self.master_secrets.get(version)

    def to_json(self) -> dict:
        return {
            "key_id": self.key_id,
            "current_version": self.current_version,
            "created_at": self.created_at,
            "master_secrets": {
                str(v): base64.b64encode(secret).decode("ascii")
                for v, secret in sorted(self.master_secrets.items())
            },
        }

    @classmethod
    def from_json(cls, data: dict) -> "KeyRecord":
        record = cls(
            key_id=data["key_id"],
            current_version=int(data["current_version"]),
            created_at=data.get("created_at", ""),
        )
        for raw_version, raw_secret in data.get("master_secrets", {}).items():
            version = int(raw_version)
            record.master_secrets[version] = base64.b64decode(raw_secret)
        return record


class LocalKeyStore:
    """基于本地 JSON 文件的密钥存储（模拟 KMS 托管）。"""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> dict[str, KeyRecord]:
        """读取全部密钥；文件不存在时返回空映射。"""
        if not self.path.is_file():
            return {}
        with self.path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return {key_id: KeyRecord.from_json(item) for key_id, item in raw.items()}

    def save(self, records: dict[str, KeyRecord]) -> None:
        """全量原子落盘：先写临时文件并 fsync，再原子替换目标文件。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            key_id: record.to_json()
            for key_id, record in sorted(records.items())
        }
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.path)
        except BaseException:
            # 落盘失败时清理临时文件，目标文件保持原状
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
