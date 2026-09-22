"""本地持久化：模拟主密钥的托管与归档（原子写 JSON）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class KeyRecord:
    """一个逻辑主密钥的全部版本状态。"""

    key_id: str
    versions: list[int] = field(default_factory=list)
    current_version: int = 0
    # version -> base64 主密钥根（同一 key 下所有版本由同一根派生）
    master_secret_b64: str = ""
    created_at: str = ""


class LocalKeyStore:
    """基于本地 JSON 文件的密钥存储（模拟 KMS 托管）。"""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, KeyRecord]:
        raise NotImplementedError

    def save(self, records: dict[str, KeyRecord]) -> None:
        raise NotImplementedError
