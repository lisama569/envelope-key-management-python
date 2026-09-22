"""调用方授权策略：按操作与密钥范围授权。

动作（action）：
- key.create  / key.rotate / key.read：密钥管理
- encrypt / decrypt：密码学使用

拒绝原因区分：
- 匿名 / 未知调用方                 -> EKM_UNAUTHENTICATED (401)
- 调用方无该动作授权               -> EKM_FORBIDDEN / reason=ACTION_DENIED (403)
- 有动作授权但密钥不在授权范围     -> EKM_FORBIDDEN / reason=KEY_SCOPE_DENIED (403)
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import AuthenticationError, AuthorizationError

ACTION_KEY_CREATE = "key.create"
ACTION_KEY_ROTATE = "key.rotate"
ACTION_KEY_READ = "key.read"
ACTION_ENCRYPT = "encrypt"
ACTION_DECRYPT = "decrypt"

ALL_ACTIONS = frozenset({
    ACTION_KEY_CREATE,
    ACTION_KEY_ROTATE,
    ACTION_KEY_READ,
    ACTION_ENCRYPT,
    ACTION_DECRYPT,
})
CRYPTO_ACTIONS = frozenset({ACTION_ENCRYPT, ACTION_DECRYPT})

REASON_ACTION_DENIED = "ACTION_DENIED"
REASON_KEY_SCOPE_DENIED = "KEY_SCOPE_DENIED"


@dataclass(frozen=True)
class Policy:
    """调用方授权：允许的操作集合 + 可访问的密钥范围（空集合表示全部）。"""

    actor_id: str
    actions: frozenset[str]
    key_scope: frozenset[str]  # 空集合表示不限制

    def may_access_key(self, key_id: str) -> bool:
        return not self.key_scope or key_id in self.key_scope


# 预置策略表（本地模拟 IAM）。
DEFAULT_POLICIES: dict[str, Policy] = {
    # 管理员：全权，不限密钥
    "admin": Policy("admin", ALL_ACTIONS, frozenset()),
    # 加密方：仅对 k1/k2 做加解密
    "crypto-a": Policy("crypto-a", CRYPTO_ACTIONS, frozenset({"k1", "k2"})),
    # 加密方：仅对 k3 做加解密（演示范围隔离）
    "crypto-b": Policy("crypto-b", CRYPTO_ACTIONS, frozenset({"k3"})),
    # 只读：仅读取密钥状态，不能管理也不能加解密
    "auditor": Policy("auditor", frozenset({ACTION_KEY_READ}), frozenset()),
}


def authenticate(actor: str | None) -> str:
    """返回可信调用方标识；缺失/匿名/未知身份抛出 AuthenticationError。"""
    if not actor or not isinstance(actor, str) or not actor.strip():
        raise AuthenticationError(
            "缺少调用方身份（X-Actor 头）",
            details={"reason": "MISSING_IDENTITY"},
        )
    actor = actor.strip()
    if actor not in DEFAULT_POLICIES:
        raise AuthenticationError(
            f"未知调用方身份: {actor}",
            details={"reason": "UNKNOWN_IDENTITY", "actor": actor},
        )
    return actor


def authorize(actor: str, action: str, key_id: str) -> Policy:
    """先校验动作授权，再校验密钥范围；越权原因分别可区分。"""
    policy = DEFAULT_POLICIES[actor]
    if action not in policy.actions:
        raise AuthorizationError(
            f"调用方 {actor} 无权执行动作 {action}",
            details={
                "reason": REASON_ACTION_DENIED,
                "actor": actor,
                "action": action,
            },
        )
    if not policy.may_access_key(key_id):
        raise AuthorizationError(
            f"调用方 {actor} 无权访问密钥 {key_id}",
            details={
                "reason": REASON_KEY_SCOPE_DENIED,
                "actor": actor,
                "action": action,
                "key_id": key_id,
                "allowed_scope": sorted(policy.key_scope),
            },
        )
    return policy
