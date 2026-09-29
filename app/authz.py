"""按调用方区分的操作授权（线程安全，可选持久化）。"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from app.errors import AuthorizationError, KeyScopeError
from app.persistence import atomic_write_json, ensure_state_dir, read_json, state_path

# 操作 -> 需要的权限属性
_OP_PERMISSION = {
    "create": "can_create",
    "rotate": "can_rotate",
    "retire": "can_rotate",  # 退役与轮换同属密钥管理操作
    "encrypt": None,  # 仅需在密钥授权范围内
    "decrypt": None,
    "migrate": None,  # 历史密文迁移：需对涉及的 key_id 有解密/加密范围
}

_AUTHZ_FILE = "callers.json"


@dataclass(frozen=True)
class Caller:
    """调用方身份与其授权范围。"""

    name: str
    allowed_key_ids: frozenset[str] = field(default_factory=frozenset)
    can_rotate: bool = False
    can_create: bool = False


class Authorizer:
    """注册调用方并校验其是否可对指定密钥执行指定操作。

    传入 state_dir 时把调用方注册表落盘，重启后随其他状态一并恢复。
    """

    def __init__(self, state_dir: str | None = None) -> None:
        self._lock = threading.RLock()
        self._state_dir = ensure_state_dir(state_dir)
        self._path = state_path(self._state_dir, _AUTHZ_FILE)
        self._callers: dict[str, Caller] = {}
        with self._lock:
            self._load()

    def _load(self) -> None:
        data = read_json(self._path) if self._path else None
        if not data:
            return
        for item in data:
            self._callers[item["name"]] = Caller(
                name=item["name"],
                allowed_key_ids=frozenset(item["allowed_key_ids"]),
                can_rotate=item.get("can_rotate", False),
                can_create=item.get("can_create", False),
            )

    def _save(self) -> None:
        if self._path is None:
            return
        payload = [
            {
                "name": c.name,
                "allowed_key_ids": sorted(c.allowed_key_ids),
                "can_rotate": c.can_rotate,
                "can_create": c.can_create,
            }
            for c in self._callers.values()
        ]
        atomic_write_json(self._path, payload)

    def register(self, caller: Caller) -> None:
        with self._lock:
            self._callers[caller.name] = caller
            self._save()

    def check(self, caller_name: str, key_id: str, operation: str) -> Caller:
        """校验通过返回 Caller；否则抛出 AuthorizationError/KeyScopeError。"""
        with self._lock:
            caller = self._callers.get(caller_name)
            if caller is None:
                raise AuthorizationError(f"unknown caller: {caller_name!r}")
            if operation not in _OP_PERMISSION:
                raise AuthorizationError(f"unknown operation: {operation!r}")
            if key_id not in caller.allowed_key_ids:
                raise KeyScopeError(
                    f"caller {caller_name!r} is not authorized for key {key_id!r}"
                )
            perm = _OP_PERMISSION[operation]
            if perm is not None and not getattr(caller, perm):
                raise AuthorizationError(
                    f"caller {caller_name!r} lacks permission for operation {operation!r}"
                )
            return caller
