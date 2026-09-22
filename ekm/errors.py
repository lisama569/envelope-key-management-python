"""信封密钥管理服务的可区分错误分类。

所有业务异常都携带稳定的 ``code``（供调用方按原因分支处理）与 HTTP 状态码，
``details`` 用于补充定位信息（如密钥版本）。
"""


class EKMError(Exception):
    """EKM 业务错误基类。"""

    code: str = "EKM_INTERNAL"
    http_status: int = 500

    def __init__(self, message: str = "", *, details: dict | None = None) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code
        self.details = details or {}


class AuthenticationError(EKMError):
    """调用方身份缺失或不可信。"""

    code = "EKM_UNAUTHENTICATED"
    http_status = 401


class AuthorizationError(EKMError):
    """已认证调用方无权执行该操作或访问该密钥。"""

    code = "EKM_FORBIDDEN"
    http_status = 403


class KeyNotFoundError(EKMError):
    """请求的密钥或版本不存在 / 已不可用。"""

    code = "EKM_KEY_VERSION_NOT_FOUND"
    http_status = 404


class MalformedEnvelopeError(EKMError):
    """封装元数据结构损坏或缺少字段。"""

    code = "EKM_MALFORMED_ENVELOPE"
    http_status = 400


class MetadataTamperedError(EKMError):
    """封装元数据（头部）被篡改。"""

    code = "EKM_METADATA_TAMPERED"
    http_status = 400


class AadTamperedError(EKMError):
    """附加数据（AAD）被篡改。"""

    code = "EKM_AAD_TAMPERED"
    http_status = 400


class CiphertextTamperedError(EKMError):
    """密文或 GCM 认证标签被篡改。"""

    code = "EKM_CIPHERTEXT_TAMPERED"
    http_status = 400


class AuditVerificationError(EKMError):
    """审计链校验失败：记录缺失、断链或被改写。"""

    code = "EKM_AUDIT_VERIFICATION_FAILED"
    http_status = 500
