"""数据模型：密钥版本、密钥状态、信封、审计记录、迁移结果。"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class KeyStatus(enum.Enum):
    """密钥版本的生命周期状态。"""

    ACTIVE = "active"      # 唯一可用于新加密的版本
    ARCHIVED = "archived"  # 历史版本：可解密历史密文，等待迁移/退役
    RETIRED = "retired"    # 已显式退役：不可再用于解密（与"版本不存在"区分）


class MigrationStatus(enum.Enum):
    """批次中单个密文项的迁移状态。"""

    PENDING = "pending"        # 已登记，尚未成功迁移
    MIGRATED = "migrated"      # 已重新加密到登记时的活跃版本
    ALREADY_CURRENT = "already_current"  # 提交时就已经是活跃版本，无需迁移
    FAILED = "failed"          # 尝试过但未成功（如解密失败），可重试


@dataclass(frozen=True)
class KeyVersion:
    """一个不可变的密钥版本。"""

    key_id: str
    version: int
    status: KeyStatus
    material: bytes = field(repr=False)  # 主密钥材料，不进入日志
    created_at: float = 0.0


@dataclass(frozen=True)
class Envelope:
    """信封加密结果：携带定位密钥版本所需的全部元数据。"""

    key_id: str
    key_version: int
    iv: bytes
    ciphertext: bytes
    tag: bytes
    aad: bytes  # 附加认证数据（调用方提供的上下文）


@dataclass(frozen=True)
class AuditRecord:
    """一次密钥状态变更的可核验审计记录（哈希链）。"""

    seq: int
    timestamp: float
    caller: str
    action: str
    key_id: str
    detail: str
    prev_hash: str
    record_hash: str


@dataclass(frozen=True)
class MigrationItemResult:
    """批次中一个密文项的迁移结果。"""

    index: int
    fingerprint: str
    source_version: int
    status: MigrationStatus
    target_version: Optional[int] = None
    envelope: Optional[Envelope] = None  # 迁移后的信封；FAILED/PENDING 时为 None
    error: Optional[str] = None


@dataclass(frozen=True)
class MigrationReport:
    """一次批次提交（可能是重试）的完整迁移报告。"""

    batch_id: str
    key_id: str
    active_version: int
    items: list[MigrationItemResult] = field(default_factory=list)

    @property
    def migrated(self) -> list[MigrationItemResult]:
        return [i for i in self.items if i.status is MigrationStatus.MIGRATED]

    @property
    def already_current(self) -> list[MigrationItemResult]:
        return [i for i in self.items if i.status is MigrationStatus.ALREADY_CURRENT]

    @property
    def failed(self) -> list[MigrationItemResult]:
        return [i for i in self.items if i.status is MigrationStatus.FAILED]

    @property
    def pending(self) -> list[MigrationItemResult]:
        return [i for i in self.items if i.status is MigrationStatus.PENDING]

    @property
    def complete(self) -> bool:
        """批次内没有未成功项（PENDING/FAILED）即视为完成。"""
        return not self.failed and not self.pending
