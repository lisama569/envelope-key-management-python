"""可区分的错误分类：所有密钥管理/信封加密相关的错误类型。"""

from __future__ import annotations


class KeyManagementError(Exception):
    """所有密钥管理错误的基类。"""

    code: str = "key_management_error"


class KeyNotFoundError(KeyManagementError):
    """请求引用的密钥版本不存在（或已不可用于解密）。"""

    code: str = "key_not_found"


class NoActiveKeyError(KeyManagementError):
    """没有可用于加密的活跃密钥版本。"""

    code: str = "no_active_key"


class AuthorizationError(KeyManagementError):
    """调用方身份未知或未被授予该操作。"""

    code: str = "authorization_error"


class KeyScopeError(AuthorizationError):
    """调用方已认证，但目标密钥不在其授权范围内。"""

    code: str = "key_scope_error"


class IntegrityError(KeyManagementError):
    """密文、附加数据或封装元数据被篡改，完整性校验失败。"""

    code: str = "integrity_error"


class EnvelopeFormatError(KeyManagementError):
    """封装格式无法解析（版本、字段缺失或类型错误）。"""

    code: str = "envelope_format_error"


class KeyRetiredError(KeyManagementError):
    """密钥版本已显式退役，不再允许用于解密。

    与 KeyNotFoundError（版本根本不存在）和 AuthorizationError/KeyScopeError
    （调用方越权）明确区分，调用方可以据此判断密文需要先重新迁移。
    """

    code: str = "key_retired"


class RetirementBlockedError(KeyManagementError):
    """版本尚不能退役：仍有未迁完的历史密文或上一次迁移有未成功的项。"""

    code: str = "retirement_blocked"


class MigrationBatchMismatchError(KeyManagementError):
    """用同一批次号重试时提交的密文集合与首次提交不一致。"""

    code: str = "migration_batch_mismatch"
