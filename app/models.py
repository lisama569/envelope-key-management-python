"""数据模型：密钥版本、密钥状态、信封、审计记录。"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class KeyStatus(enum.Enum):
    """密钥版本的生命周期状态。"""

    ACTIVE = "active"      # 唯一可用于新加密的版本
    ARCHIVED = "archived"  # 仅可用于解密历史密文


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
