"""按调用方区分的操作授权。"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.errors import AuthorizationError, KeyScopeError

# 操作 -> 需要的权限属性
_OP_PERMISSION = {
    "create": "can_create",
    "rotate": "can_rotate",
    "retire": "can_rotate",  # 退役与轮换同级，属于密钥生命周期管理
    "migrate": None,  # 数据迁移只需在密钥授权范围内
    "encrypt": None,  # 仅需在密钥授权范围内
    "decrypt": None,
}


@dataclass(frozen=True)
class Caller:
    """调用方身份与其授权范围。"""

    name: str
    allowed_key_ids: frozenset[str] = field(default_factory=frozenset)
    can_rotate: bool = False
    can_create: bool = False


class Authorizer:
    """注册调用方并校验其是否可对指定密钥执行指定操作。"""

    def __init__(self) -> None:
        self._callers: dict[str, Caller] = {}

    def register(self, caller: Caller) -> None:
        self._callers[caller.name] = caller

    def check(self, caller_name: str, key_id: str, operation: str) -> Caller:
        """校验通过返回 Caller；否则抛出 AuthorizationError/KeyScopeError。"""
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
