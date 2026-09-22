"""授权：匿名拒绝、动作越权、密钥范围越权三类原因可区分。"""

from __future__ import annotations

import logging

import pytest

from ekm.authz import (
    REASON_ACTION_DENIED,
    REASON_KEY_SCOPE_DENIED,
    authenticate,
    authorize,
)
from ekm.errors import AuthenticationError, AuthorizationError

logger = logging.getLogger(__name__)


def test_anonymous_rejected() -> None:
    with pytest.raises(AuthenticationError) as ei:
        authenticate(None)
    logger.info("匿名请求拒绝原因=%s", ei.value.code)
    with pytest.raises(AuthenticationError):
        authenticate("ghost")


def test_action_denied_distinct() -> None:
    actor = authenticate("crypto-a")
    with pytest.raises(AuthorizationError) as ei:
        authorize(actor, "key.rotate", "k1")
    assert ei.value.details["reason"] == REASON_ACTION_DENIED
    logger.info("crypto-a 轮换密钥被拒 reason=%s 判定依据=动作不在授权集合",
                REASON_ACTION_DENIED)


def test_key_scope_denied_distinct() -> None:
    actor = authenticate("crypto-a")
    with pytest.raises(AuthorizationError) as ei:
        authorize(actor, "encrypt", "k3")
    assert ei.value.details["reason"] == REASON_KEY_SCOPE_DENIED
    logger.info("crypto-a 访问 k3 被拒 reason=%s 判定依据=k3 不在 scope={k1,k2}",
                REASON_KEY_SCOPE_DENIED)


def test_in_scope_allowed() -> None:
    assert authorize("crypto-a", "decrypt", "k2").actor_id == "crypto-a"


def test_auditor_cannot_encrypt() -> None:
    with pytest.raises(AuthorizationError) as ei:
        authorize("auditor", "encrypt", "k1")
    assert ei.value.details["reason"] == REASON_ACTION_DENIED
