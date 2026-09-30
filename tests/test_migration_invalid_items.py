"""迁移批次中的非法元素：明确拒绝、原因可区分、不暴露内部异常、不污染批次状态。"""

import logging
from dataclasses import replace

import pytest

from app.authz import Caller
from app.errors import (
    AuthorizationError,
    EnvelopeFormatError,
    KeyNotFoundError,
)
from app.service import KeyManagementService

logger = logging.getLogger("kms.test")


def _assert_distinct_rejection(exc_info, expect_index=None):
    err = exc_info.value
    logger.info("非法元素被拒绝: code=%s message=%s", err.code, err)
    # 与越权 / 版本不存在明确区分的独立拒绝原因
    assert isinstance(err, EnvelopeFormatError)
    assert not isinstance(err, (AuthorizationError, KeyNotFoundError))
    assert err.code == "envelope_format_error"
    assert err.code not in ("authorization_error", "key_scope_error", "key_not_found")
    if expect_index is not None:
        assert f"index {expect_index}" in str(err)


def test_non_envelope_elements_rejected(svc):
    env = svc.encrypt("app-orders", "orders", b"good")
    svc.rotate_key("admin", "orders")

    bad_batch = [env, "not-an-envelope", None, {"key_id": "orders"}]
    for i, bad in enumerate(bad_batch[1:], start=1):
        with pytest.raises(EnvelopeFormatError) as exc_info:
            svc.migrate_batch("app-orders", "orders", [env, bad], batch_id=f"bad-{i}")
        _assert_distinct_rejection(exc_info, expect_index=1)


def test_structurally_incomplete_envelope_rejected(svc):
    env = svc.encrypt("app-orders", "orders", b"good")
    svc.rotate_key("admin", "orders")

    malformed = [
        replace(env, key_version=0),                 # 版本号非法
        replace(env, key_id=""),                     # 空 key_id
        replace(env, iv="not-bytes"),                # 字段类型错误
        replace(env, tag=None),                      # 缺字段
    ]
    for i, bad in enumerate(malformed):
        with pytest.raises(EnvelopeFormatError) as exc_info:
            svc.migrate_batch("app-orders", "orders", [env, bad], batch_id=f"mal-{i}")
        _assert_distinct_rejection(exc_info, expect_index=1)


def test_envelope_of_other_key_rejected(svc):
    svc.create_key("admin", "payments")
    foreign = svc.encrypt("admin", "payments", b"foreign")
    env = svc.encrypt("app-orders", "orders", b"good")

    with pytest.raises(EnvelopeFormatError) as exc_info:
        svc.migrate_batch("app-orders", "orders", [env, foreign], batch_id="cross")
    _assert_distinct_rejection(exc_info, expect_index=1)
    assert "payments" in str(exc_info.value)


def test_rejection_does_not_disturb_existing_progress(svc):
    """坏数据被拒后：已迁好的状态不变，同批次号用干净数据重交可正常完成。"""
    envs = [svc.encrypt("app-orders", "orders", f"d-{i}".encode()) for i in range(3)]
    svc.rotate_key("admin", "orders")

    r1 = svc.migrate_batch("app-orders", "orders", envs, batch_id="B")
    assert r1.complete
    first_results = {i.fingerprint: i.envelope for i in r1.migrated}

    # 新批次号 + 混入坏元素 -> 拒绝；该批次号不应被污染性登记
    with pytest.raises(EnvelopeFormatError):
        svc.migrate_batch("app-orders", "orders", [envs[0], 12345], batch_id="B2")

    # 同一批次号改交干净数据：正常登记并完成（坏数据没有卡死批次号）
    r2 = svc.migrate_batch("app-orders", "orders", envs[:1], batch_id="B2")
    assert r2.complete and len(r2.migrated) == 1

    # 原批次重交：已迁好的结果原样返回，未被坏提交弄乱
    r3 = svc.migrate_batch("app-orders", "orders", envs, batch_id="B")
    assert r3.complete
    for item in r3.migrated:
        assert item.envelope is first_results[item.fingerprint]
    logger.info(
        "判定依据: 坏元素被拒后, 批次 B 的 3 项已迁结果逐字节保持, "
        "批次号 B2 用干净数据重交正常完成")


def test_no_internal_exception_leaks(svc):
    """任何非法元素都只产生 KeyManagementError 家族的可区分拒绝，不冒内部异常。"""
    env = svc.encrypt("app-orders", "orders", b"good")
    svc.rotate_key("admin", "orders")
    junk = [object(), 42, b"raw-bytes", [env], (env,)]
    for i, bad in enumerate(junk):
        try:
            svc.migrate_batch("app-orders", "orders", [bad], batch_id=f"junk-{i}")
        except EnvelopeFormatError as exc:
            logger.info("junk[%d] type=%s -> code=%s", i, type(bad).__name__, exc.code)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"内部异常泄漏: {type(exc).__name__}: {exc}")
        else:
            pytest.fail(f"非法元素未被拒绝: {bad!r}")
