"""本地文件持久化：整份状态原子写入单个 JSON 文件。

写入用"临时文件 + fsync + os.replace"完成，进程在任意时刻被杀死，
状态文件要么是上一份完整快照，要么是新的完整快照，不会出现半份状态；
服务重启后凭快照恢复密钥版本、退役状态、迁移进度与审计链，
迁移可从断点继续，状态仍自圆其说。
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Optional


class JsonStateStore:
    """把三部分状态（keystore / migrations / audit）存进同一个 JSON 文件。"""

    def __init__(self, path: str) -> None:
        self.path = path

    def load(self) -> Optional[dict]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def save(self, keystore_snap: dict, migration_snap: dict, audit_snap: dict) -> None:
        payload = {
            "version": 1,
            "keystore": keystore_snap,
            "migrations": migration_snap,
            "audit": audit_snap,
        }
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".state-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
