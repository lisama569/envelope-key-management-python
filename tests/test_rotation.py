"""轮换规则与历史密文解密。"""

import logging

import pytest

from app.errors import KeyNotFoundError
from app.models import KeyStatus

logger = logging.getLogger("kms.test")


def test_rotate_archives_previous_and_activates_new(svc):
    env1 = svc.encrypt("app-orders", "orders", b"before-rotation")
    logger.info("encrypted before rotation with key version %d", env1.key_version)

    new_version = svc.rotate_key("admin", "orders")
    versions = svc.keystore.list_versions("orders")
    statuses = {kv.version: kv.status for kv in versions}
    logger.info("after rotation: versions=%s", {v: s.value for v, s in statuses.items()})

    assert new_version == 2
    assert statuses[1] is KeyStatus.ARCHIVED, "旧版本应归档保留用于解密"
    assert statuses[2] is KeyStatus.ACTIVE, "新版本应为唯一 ACTIVE"
    assert sum(s is KeyStatus.ACTIVE for s in statuses.values()) == 1


def test_historical_ciphertext_still_decryptable(svc):
    env1 = svc.encrypt("app-orders", "orders", b"historical-secret")
    svc.rotate_key("admin", "orders")
    svc.rotate_key("admin", "orders")
    logger.info("decrypting v%d ciphertext after two rotations", env1.key_version)

    plaintext = svc.decrypt("app-orders", env1)
    assert plaintext == b"historical-secret"
    logger.info("判定依据: v%d 已归档但仍可用于解密, 解密结果与原文一致", env1.key_version)


def test_new_encryption_uses_latest_version(svc):
    svc.rotate_key("admin", "orders")
    env = svc.encrypt("app-orders", "orders", b"after-rotation")
    logger.info("post-rotation encryption used version %d (expect 2)", env.key_version)
    assert env.key_version == 2
    assert svc.decrypt("app-orders", env) == b"after-rotation"


def test_decrypt_unknown_version_rejected(svc):
    env = svc.encrypt("app-orders", "orders", b"x")
    forged = type(env)(key_id=env.key_id, key_version=99, iv=env.iv,
                       ciphertext=env.ciphertext, tag=env.tag, aad=env.aad)
    with pytest.raises(KeyNotFoundError) as exc_info:
        svc.decrypt("app-orders", forged)
    logger.info("判定依据: 版本 99 不存在 -> %s", exc_info.value.code)
    assert exc_info.value.code == "key_not_found"


def test_rotation_audited(svc):
    svc.rotate_key("admin", "orders")
    svc.rotate_key("admin", "orders")
    records = svc.audit.records()
    for r in records:
        logger.info("audit seq=%d caller=%s action=%s detail=%s",
                    r.seq, r.caller, r.action, r.detail)
    assert svc.audit.verify(), "审计哈希链必须完整可核验"
    rotates = [r for r in records if r.action == "rotate_key"]
    assert len(rotates) == 2
    assert "new_active_version=2" in rotates[0].detail
    assert "new_active_version=3" in rotates[1].detail
