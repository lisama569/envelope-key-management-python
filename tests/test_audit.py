"""审计哈希链：顺序追加、正常校验通过、改写/断链被检出。"""

from __future__ import annotations

import json
import logging

import pytest

from ekm.audit import AuditLog
from ekm.errors import AuditVerificationError

logger = logging.getLogger(__name__)


def test_append_and_verify(tmp_path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    e1 = log.append(action="key.create", actor="alice", key_id="k1", key_version=1)
    e2 = log.append(action="key.rotate", actor="alice", key_id="k1", key_version=2)
    assert e1.seq == 1 and e2.seq == 2
    assert e2.prev_hash == e1.entry_hash
    log.verify()
    logger.info("审计链自洽 seq=%d..%d 判定依据=逐条重算 SHA256(prev||body)", e1.seq, e2.seq)


def test_tampered_entry_detected(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(action="key.create", actor="alice", key_id="k1", key_version=1)
    log.append(action="key.rotate", actor="alice", key_id="k1", key_version=2)

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["actor"] = "mallory"  # 改写历史
    lines[0] = json.dumps(record, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(AuditVerificationError) as ei:
        AuditLog(path).verify()
    logger.info("改写审计 actor=alice->mallory 拒绝原因=%s", ei.value.code)


def test_broken_chain_detected(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(action="key.create", actor="alice", key_id="k1", key_version=1)
    log.append(action="key.rotate", actor="alice", key_id="k1", key_version=2)

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[1] + "\n", encoding="utf-8")  # 删除第一条
    with pytest.raises(AuditVerificationError):
        AuditLog(path).verify()
