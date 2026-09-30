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
    """注册调用方并校验其是否可对指定密钥执行指定操作。

    调用方授权与密钥版本/迁移进度一样可快照持久化：重启后谁能做什么不变。
    """

    def __init__(self, snapshot: dict | None = None) -> None:
        self._callers: dict[str, Caller] = {}
        if snapshot:
            self.restore(snapshot)

    def register(self, caller: Caller) -> None:
        # 重复注册以最新声明为准（重启引导时幂等覆盖同样安全）
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

    # ---- 快照：调用方授权随密钥/迁移/审计一起落盘，重启后授权关系不变 ----

    def snapshot(self) -> dict:
        return {"callers": [
            {
                "name": c.name,
                "allowed_key_ids": sorted(c.allowed_key_ids),
                "can_rotate": c.can_rotate,
                "can_create": c.can_create,
            }
            for c in self._callers.values()
        ]}

    def restore(self, snapshot: dict) -> None:
        """从 snapshot() 产生的结构恢复；仅在构造期调用。"""
        self._callers = {}
        for d in snapshot.get("callers", []):
            self._callers[d["name"]] = Caller(
                name=d["name"],
                allowed_key_ids=frozenset(d.get("allowed_key_ids", ())),
                can_rotate=bool(d.get("can_rotate", False)),
                can_create=bool(d.get("can_create", False)),
            )
