"""迁移批次中的坏数据：明确、可区分地拒绝，不冒内部异常，不污染已有状态。"""

import logging
from dataclasses import replace

import pytest

from app.errors import (
    AuthorizationError,
    EnvelopeFormatError,
    KeyScopeError,
)
from app.models import MigrationStatus

logger = logging.getLogger("kms.test")


def _setup(svc):
    envs = [svc.encrypt("app-orders", "orders", f"ok-{i}".encode())
            for i in range(2)]
    svc.rotate_key("admin", "orders")
    # 先让一个合法批次成功，验证坏数据不会弄坏它
    good = svc.migrate_batch("app-orders", "orders", envs, batch_id="good")
    assert good.complete
    return envs, good


@pytest.mark.parametrize("bad,label", [
    ("not-an-envelope", "str"),
    (42, "int"),
    (None, "None"),
    ({"key_id": "orders"}, "dict"),
    (["x"], "list"),
])
def test_non_envelope_elements_rejected_distinctly(svc, bad, label):
    envs, good = _setup(svc)
    with pytest.raises(EnvelopeFormatError) as exc_info:
        svc.migrate_batch("app-orders", "orders", [envs[0], bad], batch_id="bad")
    assert exc_info.value.code == "envelope_format_error"
    logger.info("坏元素类型=%s -> code=%s message=%s",
                label, exc_info.value.code, exc_info.value)


@pytest.mark.parametrize("mutator,label", [
    (lambda e: replace(e, iv=b"short"), "iv 长度错误"),
    (lambda e: replace(e, tag=b"bad-tag"), "tag 长度错误"),
    (lambda e: replace(e, ciphertext="not-bytes"), "ciphertext 非 bytes"),
    (lambda e: replace(e, aad="not-bytes"), "aad 非 bytes"),
    (lambda e: replace(e, key_version=0), "version 非法"),
    (lambda e: replace(e, key_id=""), "key_id 为空"),
])
def test_malformed_envelopes_rejected_distinctly(svc, mutator, label):
    envs, _ = _setup(svc)
    bad = mutator(envs[1])
    with pytest.raises(EnvelopeFormatError) as exc_info:
        svc.migrate_batch("app-orders", "orders", [envs[0], bad], batch_id="bad")
    assert exc_info.value.code == "envelope_format_error"
    logger.info("坏数据(%s) -> code=%s message=%s",
                label, exc_info.value.code, str(exc_info.value)[:120])


def test_foreign_key_envelope_rejected(svc):
    """元素结构合法但属于另一把密钥：明确拒绝，而不是当成 orders 的数据处理。"""
    envs, _ = _setup(svc)
    svc.create_key("admin", "payments")
    foreign = svc.encrypt("admin", "payments", b"foreign")
    with pytest.raises(EnvelopeFormatError) as exc_info:
        svc.migrate_batch("app-orders", "orders", [envs[0], foreign],
                          batch_id="bad")
    assert exc_info.value.code == "envelope_format_error"
    assert "key_id mismatch" in str(exc_info.value)
    logger.info("跨密钥信封 -> code=%s message=%s",
                exc_info.value.code, exc_info.value)


def test_rejection_does_not_register_batch_or_touch_state(svc):
    """坏数据必须整体拒绝：批次不登记，同 batch_id 随后可正常使用，已成功批次不变。"""
    envs, good = _setup(svc)
    bad = replace(envs[1], tag=b"\x00" * 8)  # 结构不完整（tag 长度错）

    with pytest.raises(EnvelopeFormatError):
        svc.migrate_batch("app-orders", "orders", [envs[0], bad], batch_id="will-reuse")

    # 批次未登记：同一 batch_id 提交合法集合应直接作为新批次成功（不报 mismatch）
    report = svc.migrate_batch("app-orders", "orders", envs, batch_id="will-reuse")
    assert report.complete and len(report.migrated) == 2
    # 之前成功的批次结果原样保留（坏数据没把它弄乱/卡死）
    again = svc.migrate_batch("app-orders", "orders", envs, batch_id="good")
    assert [i.envelope for i in again.migrated] == \
           [i.envelope for i in good.migrated]
    assert all(i.status in (MigrationStatus.MIGRATED, MigrationStatus.ALREADY_CURRENT)
               for i in again.items)
    # 坏数据没有制造出阻塞退役的失败项；全迁完后退役可以放行
    assert svc.retire_key("admin", "orders", 1) == 1
    logger.info("判定依据: 坏数据整体拒绝且批次未登记, 已成功批次字节级不变, 退役不被污染")


def test_format_error_distinct_from_authz_scope_and_not_found(svc):
    """envelope_format_error 与越权、密钥范围、版本不存在三类拒绝可稳定区分。"""
    envs, _ = _setup(svc)
    bad = replace(envs[1], iv=b"x")

    # 未登记调用方 -> authorization_error（先于格式校验）
    with pytest.raises(AuthorizationError) as exc:
        svc.migrate_batch("ghost", "orders", [bad], batch_id="b")
    assert exc.value.code == "authorization_error"

    # 超出密钥范围 -> key_scope_error（先于格式校验）
    with pytest.raises(KeyScopeError) as exc:
        svc.migrate_batch("app-orders", "payments", [bad], batch_id="b")
    assert exc.value.code == "key_scope_error"

    # 认证与范围通过后，坏元素 -> envelope_format_error
    with pytest.raises(EnvelopeFormatError) as exc:
        svc.migrate_batch("app-orders", "orders", [bad], batch_id="b")
    assert exc.value.code == "envelope_format_error"

    # 对照：结构合法、但引用版本不存在的信封在登记后按既有失败路径处理，
    # 不与格式拒绝混淆（报告项 FAILED，原因里带 source version not found）。
    missing = replace(envs[0], key_version=99)
    report = svc.migrate_batch("app-orders", "orders", [missing], batch_id="missing")
    assert len(report.failed) == 1
    assert "not found" in report.failed[0].error
    logger.info("判定依据: 四类拒绝码可区分: authorization_error / key_scope_error / "
                "envelope_format_error(整批拒绝) / 版本不存在(逐项 FAILED: %s)",
                report.failed[0].error)


def test_unknown_caller_with_bad_data_is_authz_error(svc):
    """坏数据不能盖过授权判定：未认证调用方永远先收到授权拒绝。"""
    with pytest.raises(AuthorizationError):
        svc.migrate_batch("ghost", "orders", ["junk"], batch_id="b")
