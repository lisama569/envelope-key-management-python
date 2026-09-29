"""本地状态持久化：JSON 文件 + 原子替换写，支持崩溃后的状态恢复。

只用于本地模拟：进程重启后用同一个 state_dir 重新构造组件，
即可读回密钥版本、退役状态、迁移进度与审计记录。
每次写入都先写临时文件再 os.replace，崩溃最多留下旧文件，不会出现半写文件。
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any


def ensure_state_dir(state_dir: str | None) -> str | None:
    """确保状态目录存在；state_dir 为 None 时表示纯内存模式。"""
    if state_dir is None:
        return None
    os.makedirs(state_dir, exist_ok=True)
    return state_dir


def state_path(state_dir: str | None, name: str) -> str | None:
    if state_dir is None:
        return None
    return os.path.join(state_dir, name)


def atomic_write_json(path: str, payload: Any) -> None:
    """先写同目录临时文件再原子替换：读到的永远是完整的上一版。"""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=1)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def read_json(path: str) -> Any | None:
    """读 JSON；文件不存在时返回 None。"""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
