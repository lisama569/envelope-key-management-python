"""调用方授权策略：按操作与密钥范围授权。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    """调用方授权：允许的操作集合 + 可访问的密钥范围（空集合表示全部）。"""

    actor_id: str
    actions: frozenset[str]
    key_scope: frozenset[str]  # 空集合表示不限制


# 预置策略表（本地模拟 IAM）
DEFAULT_POLICIES: dict[str, Policy] = {}


def authenticate(actor: str | None) -> str:
    """返回可信调用方标识；缺失/匿名抛出 AuthenticationError。"""
    raise NotImplementedError


def authorize(actor: str, action: str, key_id: str) -> Policy:
    """校验操作与密钥范围；越权抛出 AuthorizationError。"""
    raise NotImplementedError
