"""密钥管理服务：主密钥创建、轮换、版本归档、信封加解密、审计。

并发与一致性模型：
- 单一 ``RLock`` 串行化所有会改变密钥状态的操作（创建/轮换），
  并在同一把锁内完成「生成新版本 -> 持久化 -> 切换 current_version -> 写审计」，
  因此外部观察到的状态跃迁是原子的：要么停留在旧版本，要么新版本已完全就绪。
- 加密只在锁内读取 current_version 快照，随后使用该（已归档、不可变）版本密钥
  在锁外完成计算。即使此刻发生轮换，所用版本也已永久归档，密文永远可解密，
  且不存在「没有任何可用版本」的窗口（首个版本在创建时即就绪）。
- 解密按信封内 key_id/key_version 定位归档版本，与 current_version 无关，
  因此历史密文在任意次轮换后仍可解密。
- 轮换支持幂等键：同一 idempotency_key 的重复/重试返回同一结果，不会制造新版本。
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import authz, crypto
from .audit import AuditLog
from .errors import (
    AuthorizationError,
    IdempotencyConflictError,
    KeyAlreadyExistsError,
    KeyNotFoundError,
    MalformedEnvelopeError,
)
from .storage import KeyRecord, LocalKeyStore

logger = logging.getLogger(__name__)


class KeyManagementService:
    """线程安全的本地信封密钥管理服务。"""

    def __init__(self, storage_dir: str | Path = "data/ekm") -> None:
        storage_dir = Path(storage_dir)
        self.store = LocalKeyStore(storage_dir / "keys.json")
        self.audit = AuditLog(storage_dir / "audit.jsonl")
        self._lock = threading.RLock()
        self._records: dict[str, KeyRecord] = self.store.load()
        # idempotency_key -> {"key_id","key_version","action"}
        self._idempotency: dict[str, dict] = {}

    # ---------- 内部辅助 ----------

    def _get_record(self, key_id: str) -> KeyRecord:
        record = self._records.get(key_id)
        if record is None:
            raise KeyNotFoundError(
                f"密钥不存在: {key_id}", details={"key_id": key_id}
            )
        return record

    def _version_key(self, record: KeyRecord, version: int) -> bytes:
        secret = record.secret_for(version)
        if secret is None:
            raise KeyNotFoundError(
                f"密钥 {record.key_id} 的版本 v{version} 不存在或已归档销毁",
                details={"key_id": record.key_id, "key_version": version},
            )
        return crypto.derive_version_key(secret, record.key_id, version)

    def _persist_locked(self) -> None:
        self.store.save(self._records)

    def _check_and_audit_denial(self, actor, action, key_id) -> None:
        """认证+授权；拒绝时留审计并抛错。成功返回 Policy。"""
        actor_id = authz.authenticate(actor)
        try:
            policy = authz.authorize(actor_id, action, key_id)
        except AuthorizationError as exc:
            with self._lock:
                self.audit.append(
                    action="authz.deny",
                    actor=actor_id,
                    key_id=key_id,
                    key_version=0,
                    detail=f"denied_action={action} reason={exc.details.get('reason')}",
                )
            logger.warning("拒绝越权 actor=%s action=%s key=%s reason=%s code=%s",
                           actor_id, action, key_id, exc.details.get("reason"), exc.code)
            raise
        return policy

    # ---------- 密钥生命周期 ----------

    def create_key(self, *, actor: str | None, key_id: str) -> dict:
        policy = self._check_and_audit_denial(actor, authz.ACTION_KEY_CREATE, key_id)
        with self._lock:
            if key_id in self._records:
                # 重复创建视为冲突，保持状态幂等可解释
                raise KeyAlreadyExistsError(
                    f"密钥已存在: {key_id}", details={"key_id": key_id}
                )
            version = 1
            record = KeyRecord(
                key_id=key_id,
                current_version=version,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            record.master_secrets[version] = crypto.generate_master_secret()
            self._records[key_id] = record
            self._persist_locked()
            entry = self.audit.append(
                action="key.create", actor=policy.actor_id,
                key_id=key_id, key_version=version,
                detail="initial version created",
            )
            logger.info("创建密钥 actor=%s key_id=%s current=v%s audit_seq=%s",
                        policy.actor_id, key_id, version, entry.seq)
            return self.get_key_status(actor=actor, key_id=key_id)

    def rotate_key(self, *, actor: str | None, key_id: str,
                   idempotency_key: str | None = None) -> dict:
        policy = self._check_and_audit_denial(actor, authz.ACTION_KEY_ROTATE, key_id)
        with self._lock:
            # 幂等：同一幂等键的重试不产生新版本
            if idempotency_key is not None and idempotency_key in self._idempotency:
                token = self._idempotency[idempotency_key]
                if token["key_id"] != key_id or token["action"] != "key.rotate":
                    raise IdempotencyConflictError("幂等键绑定了不同的轮换请求")
                logger.info("轮换幂等命中 actor=%s key=%s 返回 v%s（不新建版本）",
                            policy.actor_id, key_id, token["key_version"])
                return self.get_key_status(actor=actor, key_id=key_id)

            record = self._get_record(key_id)
            new_version = record.current_version + 1
            # 1) 新版本密钥就绪并归档（旧版本保留）
            record.master_secrets[new_version] = crypto.generate_master_secret()
            # 2) 持久化全部版本（此时即使进程崩溃，新版本也已可用）
            self._persist_locked()
            # 3) 切换当前加密版本（原子赋值）
            record.current_version = new_version
            self._persist_locked()
            # 4) 审计
            entry = self.audit.append(
                action="key.rotate", actor=policy.actor_id,
                key_id=key_id, key_version=new_version,
                detail=f"previous_version={new_version - 1} retained_for_decrypt",
            )
            if idempotency_key is not None:
                self._idempotency[idempotency_key] = {
                    "key_id": key_id, "key_version": new_version,
                    "action": "key.rotate",
                }
            logger.info("轮换密钥 actor=%s key_id=%s new_current=v%s archived=%s audit_seq=%s",
                        policy.actor_id, key_id, new_version, record.versions(), entry.seq)
            return self.get_key_status(actor=actor, key_id=key_id)

    def get_key_status(self, *, actor: str | None, key_id: str) -> dict:
        self._check_and_audit_denial(actor, authz.ACTION_KEY_READ, key_id)
        with self._lock:
            record = self._get_record(key_id)
            return {
                "key_id": record.key_id,
                "current_version": record.current_version,
                "active_version": record.current_version,
                "versions": record.versions(),
                "created_at": record.created_at,
            }

    # ---------- 信封加解密 ----------

    def encrypt(self, *, actor: str | None, key_id: str,
                plaintext: bytes, aad: bytes = b"") -> dict:
        policy = self._check_and_audit_denial(actor, authz.ACTION_ENCRYPT, key_id)
        # 锁内仅取「当前版本」快照；版本密钥不可变，计算放到锁外也安全
        with self._lock:
            record = self._get_record(key_id)
            version = record.current_version
            if version == 0:
                raise KeyNotFoundError(
                    f"密钥 {key_id} 尚无可用版本", details={"key_id": key_id}
                )
            version_key = self._version_key(record, version)

        envelope = crypto.encrypt_blob(
            version_key=version_key, key_id=key_id, key_version=version,
            plaintext=plaintext, aad=aad,
        )
        logger.info("加密 actor=%s key_id=%s 使用版本=v%s（当前加密版本） 判定依据=current_version 快照",
                    policy.actor_id, key_id, version)
        return envelope.to_dict()

    def decrypt(self, *, actor: str | None, envelope: dict,
                expected_aad: bytes | None = None) -> bytes:
        # 先解析信封定位密钥，再以该密钥做范围授权
        if not isinstance(envelope, dict):
            raise MalformedEnvelopeError("信封必须是 JSON 对象")
        key_id = envelope.get("key_id")
        key_version = envelope.get("key_version")
        if not isinstance(key_id, str) or not isinstance(key_version, int) \
                or isinstance(key_version, bool):
            raise MalformedEnvelopeError("信封缺少合法的 key_id/key_version")

        policy = self._check_and_audit_denial(actor, authz.ACTION_DECRYPT, key_id)
        with self._lock:
            record = self._get_record(key_id)
            version_key = self._version_key(record, key_version)
            is_current = record.current_version == key_version

        logger.info("解密 actor=%s key_id=%s 定位版本=v%s %s 判定依据=信封携带 key_id/key_version 查归档",
                    policy.actor_id, key_id, key_version,
                    "(当前版本)" if is_current else "(历史归档版本)")
        return crypto.decrypt_blob(
            version_key=version_key, envelope=envelope,
            expected_aad=expected_aad,
        )

    # ---------- 审计校验 ----------

    def verify_audit(self, *, actor: str | None) -> None:
        actor_id = authz.authenticate(actor)
        # 仅管理员可核验审计
        if authz.ACTION_KEY_CREATE not in authz.DEFAULT_POLICIES[actor_id].actions:
            raise AuthorizationError(
                f"调用方 {actor_id} 无权核验审计链",
                details={"reason": "ACTION_DENIED", "actor": actor_id},
            )
        self.audit.verify()
        logger.info("审计链核验通过 actor=%s", actor_id)
