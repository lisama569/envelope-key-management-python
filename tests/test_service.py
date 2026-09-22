"""主密钥生命周期 / 轮换 / 版本归档 / 历史密文解密 / 幂等。"""

from __future__ import annotations

import logging

import pytest

from ekm.errors import (
    AuthorizationError,
    KeyAlreadyExistsError,
    KeyNotFoundError,
)

logger = logging.getLogger(__name__)


def test_create_key_initial_version(service) -> None:
    status = service.create_key(actor="admin", key_id="k1")
    assert status["current_version"] == 1
    assert status["versions"] == [1]
    logger.info("创建后状态 key=k1 versions=%s active=v%s",
                status["versions"], status["active_version"])


def test_duplicate_create_rejected(service) -> None:
    service.create_key(actor="admin", key_id="k1")
    with pytest.raises(KeyAlreadyExistsError):
        service.create_key(actor="admin", key_id="k1")


def test_rotate_archives_old_versions(service) -> None:
    service.create_key(actor="admin", key_id="k1")
    env_v1 = service.encrypt(actor="crypto-a", key_id="k1",
                             plaintext=b"old", aad=b"t1")
    assert env_v1["key_version"] == 1

    service.rotate_key(actor="admin", key_id="k1")
    status = service.get_key_status(actor="admin", key_id="k1")
    assert status["current_version"] == 2
    assert status["versions"] == [1, 2]

    env_v2 = service.encrypt(actor="crypto-a", key_id="k1",
                             plaintext=b"new", aad=b"t2")
    assert env_v2["key_version"] == 2

    # 历史密文（v1）在轮换后仍可解密
    assert service.decrypt(actor="crypto-a", envelope=env_v1,
                           expected_aad=b"t1") == b"old"
    assert service.decrypt(actor="crypto-a", envelope=env_v2,
                           expected_aad=b"t2") == b"new"
    logger.info("轮换后：v1 密文用归档版本解密、新密文用 v2；versions=%s active=v2",
                status["versions"])


def test_many_rotations_decrypt_all_history(service) -> None:
    service.create_key(actor="admin", key_id="k1")
    envelopes = []
    for i in range(5):
        envelopes.append(service.encrypt(
            actor="crypto-a", key_id="k1",
            plaintext=f"msg-{i}".encode(), aad=f"aad-{i}".encode()))
        service.rotate_key(actor="admin", key_id="k1")
    status = service.get_key_status(actor="admin", key_id="k1")
    assert status["versions"] == [1, 2, 3, 4, 5, 6]
    for i, env in enumerate(envelopes):
        pt = service.decrypt(actor="crypto-a", envelope=env,
                             expected_aad=f"aad-{i}".encode())
        assert pt == f"msg-{i}".encode()
    logger.info("5 次轮换后全部 %d 份历史密文均可解密，归档版本=%s",
                len(envelopes), status["versions"])


def test_rotate_idempotency_key(service) -> None:
    service.create_key(actor="admin", key_id="k1")
    s1 = service.rotate_key(actor="admin", key_id="k1", idempotency_key="idem-1")
    s2 = service.rotate_key(actor="admin", key_id="k1", idempotency_key="idem-1")
    assert s1["current_version"] == s2["current_version"] == 2
    entries = service.audit.read_all()
    rotations = [e for e in entries if e.action == "key.rotate"]
    assert len(rotations) == 1  # 重试不产生新状态/新审计
    logger.info("同幂等键重试两次，仅 1 条 key.rotate 审计，current 保持 v2")


def test_operations_on_unknown_key(service) -> None:
    # k2 在 crypto-a 授权范围内但不存在：先过授权再得到 not-found（不泄露存在性）
    with pytest.raises(KeyNotFoundError):
        service.encrypt(actor="crypto-a", key_id="k2", plaintext=b"x")
    with pytest.raises(KeyNotFoundError):
        service.get_key_status(actor="admin", key_id="ghost")


def test_crypto_caller_cannot_rotate(service) -> None:
    service.create_key(actor="admin", key_id="k1")
    with pytest.raises(AuthorizationError) as ei:
        service.rotate_key(actor="crypto-a", key_id="k1")
    assert ei.value.details["reason"] == "ACTION_DENIED"
    # 被拒尝试也留下审计
    denials = [e for e in service.audit.read_all() if e.action == "authz.deny"]
    assert denials and denials[-1].detail.startswith("denied_action=key.rotate")
    logger.info("越权轮换被拒 code=%s 且已写 authz.deny 审计", ei.value.code)


def test_state_survives_reload(service, tmp_path) -> None:
    from ekm.service import KeyManagementService

    service.create_key(actor="admin", key_id="k1")
    service.rotate_key(actor="admin", key_id="k1")
    env = service.encrypt(actor="crypto-a", key_id="k1",
                          plaintext=b"persist", aad=b"a")

    restarted = KeyManagementService(storage_dir=service.store.path.parent)
    assert restarted.get_key_status(actor="admin", key_id="k1")["current_version"] == 2
    assert restarted.decrypt(actor="crypto-a", envelope=env,
                             expected_aad=b"a") == b"persist"
    restarted.audit.verify()
