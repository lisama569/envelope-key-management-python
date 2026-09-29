"""数据模型：密钥版本、密钥状态、信封、审计记录。"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class KeyStatus(enum.Enum):
    """密钥版本的生命周期状态。"""

    ACTIVE = "active"      # 唯一可用于新加密的版本
    ARCHIVED = "archived"  # 仅可用于解密历史密文
    RETIRED = "retired"    # 已退役：既不可加密，也不可再用于解密


class MigrationStatus(enum.Enum):
    """单个迁移项（以原始密文指纹为键）的状态机。"""

    PENDING = "pending"                # 已登记，尚未开始（含崩溃恢复后的中断项）
    PROCESSING = "processing"          # 正在迁移（崩溃残留状态，重启后回退为 PENDING）
    MIGRATED = "migrated"              # 已成功迁移到某个目标版本（终态，不再重复迁）
    FAILED = "failed"                  # 上次尝试失败，可重试
    ALREADY_CURRENT = "already_current"  # 提交时本就处于当前活跃版本，无需迁移


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
class MigrationItem:
    """一批迁移请求中的单个输入项（对应提交列表中的一个位置）。"""

    index: int          # 在提交批次中的下标，用于结果按原序对齐
    envelope: Envelope  # 调用方提交的旧密文信封


@dataclass(frozen=True)
class MigrationRecord:
    """以原始密文指纹为键的迁移登记项：幂等与恢复都依赖它。"""

    fingerprint: str
    key_id: str
    source_version: int            # 原始密文所使用的密钥版本
    status: MigrationStatus
    target_version: int | None = None  # 成功迁移后所落到的版本
    result: Envelope | None = None     # 成功迁移后的新信封（同格式）
    attempts: int = 0                  # 累计尝试次数
    last_error: str | None = None      # 最近一次失败原因
    updated_at: float = 0.0


@dataclass(frozen=True)
class MigrationItemResult:
    """单个迁移项的处理结果，按提交原序返回。"""

    index: int
    status: MigrationStatus
    key_id: str
    source_version: int
    target_version: int | None
    envelope: Envelope | None     # 成功时：迁移后的新信封；失败/无效时为 None
    error: str | None = None


@dataclass(frozen=True)
class MigrationBatchResult:
    """一批迁移请求的汇总结果。"""

    items: list[MigrationItemResult]

    @property
    def migrated(self) -> list[MigrationItemResult]:
        """本次或此前已成功迁移的项。"""
        return [i for i in self.items if i.status
                in (MigrationStatus.MIGRATED, MigrationStatus.ALREADY_CURRENT)]

    @property
    def failed(self) -> list[MigrationItemResult]:
        """仍未成功的项（FAILED/PENDING/PROCESSING）。"""
        return [i for i in self.items if i.status
                not in (MigrationStatus.MIGRATED, MigrationStatus.ALREADY_CURRENT)]
