"""密钥管理服务门面：组合存储、加密、授权、迁移登记与审计。"""

from __future__ import annotations

import logging
import threading

from app.audit import AuditLog
from app.authz import Authorizer
from app.crypto import EnvelopeCipher
from app.errors import (
    EnvelopeFormatError,
    KeyManagementError,
    KeyNotFoundError,
    KeyVersionRetiredError,
    NoActiveKeyError,
    RetirementBlockedError,
)
from app.keystore import LocalKeyStore
from app.migration import MigrationRegistry, envelope_fingerprint
from app.models import (
    Envelope,
    MigrationBatchResult,
    MigrationItemResult,
    MigrationStatus,
)

logger = logging.getLogger("kms")


class KeyManagementService:
    """对外暴露 create/rotate/encrypt/decrypt/migrate_batch/retire_version。

    所有状态变更均审计。传入 state_dir 时，密钥状态、迁移进度与审计链
    都持久化到该目录；用同一目录重建实例即等价于"进程重启后恢复"。

    迁移与退役共用一把可重入锁串行化：保证把关判断与状态转移原子，
    重复提交同一批密文不会重复迁移；迁移与 rotate/encrypt/decrypt 之间
    不加锁——它们各自只依赖 keystore 锁内原子快照，允许真正并发。
    """

    def __init__(
        self,
        keystore: LocalKeyStore | None = None,
        cipher: EnvelopeCipher | None = None,
        authorizer: Authorizer | None = None,
        audit: AuditLog | None = None,
        migrations: MigrationRegistry | None = None,
        state_dir: str | None = None,
    ) -> None:
        self._keystore = keystore or LocalKeyStore(state_dir)
        self._cipher = cipher or EnvelopeCipher()
        self._authorizer = authorizer or Authorizer(state_dir)
        self._audit = audit or AuditLog(state_dir)
        self._migrations = migrations or MigrationRegistry(state_dir)
        self._migration_lock = threading.RLock()

    @property
    def audit(self) -> AuditLog:
        return self._audit

    @property
    def authorizer(self) -> Authorizer:
        return self._authorizer

    @property
    def keystore(self) -> LocalKeyStore:
        return self._keystore

    @property
    def migrations(self) -> MigrationRegistry:
        return self._migrations

    def create_key(self, caller: str, key_id: str) -> int:
        self._authorizer.check(caller, key_id, "create")
        try:
            kv = self._keystore.create_key(key_id)
        except ValueError as exc:
            raise KeyManagementConflictError(str(exc)) from exc
        self._audit.append(caller, "create_key", key_id,
                           f"version={kv.version} status=active")
        return kv.version

    def rotate_key(self, caller: str, key_id: str) -> int:
        self._authorizer.check(caller, key_id, "rotate")
        try:
            kv = self._keystore.rotate(key_id)
        except KeyError as exc:
            raise KeyNotFoundError(f"unknown key: {key_id}") from exc
        self._audit.append(caller, "rotate_key", key_id,
                           f"new_active_version={kv.version} previous_archived")
        logger.info("rotate key=%s new_active=v%s", key_id, kv.version)
        return kv.version

    def encrypt(self, caller: str, key_id: str, plaintext: bytes, aad: bytes = b"") -> Envelope:
        self._authorizer.check(caller, key_id, "encrypt")
        kv = self._keystore.get_active(key_id)
        if kv is None:
            raise NoActiveKeyError(f"no active key version for {key_id!r}")
        # 在取到的版本上完成加密：即使此刻发生轮换，该版本已被归档保留，
        # 密文仍可通过信封中的 (key_id, version) 定位并解密。
        return self._cipher.encrypt(kv, plaintext, aad)

    def decrypt(self, caller: str, envelope: Envelope, aad: bytes = b"") -> bytes:
        if not isinstance(envelope, Envelope) or not envelope.key_id or envelope.key_version < 1:
            raise EnvelopeFormatError("malformed envelope")
        self._authorizer.check(caller, envelope.key_id, "decrypt")
        kv = self._keystore.get_version(envelope.key_id, envelope.key_version)
        if kv is None:
            raise KeyNotFoundError(
                f"key version not found: {envelope.key_id} v{envelope.key_version}"
            )
        # RETIRED 必须与"不存在(key_not_found)"、"越权(authorization_*) "明确区分
        if kv.status.value == "retired":
            raise KeyVersionRetiredError(
                f"key version retired: {envelope.key_id} v{envelope.key_version}"
            )
        return self._cipher.decrypt(kv, envelope, aad)

    # ------------------------------------------------------------------ 迁移
    def migrate_batch(
        self, caller: str, envelopes: list[Envelope]
    ) -> MigrationBatchResult:
        """把一批历史密文迁移到当前活跃版本。

        幂等：以完整信封的指纹为键。已迁好的项直接返回上次结果，
        不重复解密/重加密；失败项可反复提交重试；已处于当前版本的项
        标记为 already_current 原样返回。输出仍是标准 Envelope，
        调用方无需感知格式变化。

        返回 MigrationBatchResult，按提交原序逐项说明状态、源版本、
        目标版本；未成功项带错误原因。
        """
        if not isinstance(envelopes, list):
            raise EnvelopeFormatError("migrate_batch expects a list of envelopes")
        results: list[MigrationItemResult] = []
        counts = {"migrated": 0, "already_current": 0, "failed": 0}
        with self._migration_lock:
            for index, env in enumerate(envelopes):
                results.append(
                    self._migrate_one(caller, index, env, counts)
                )
        self._audit.append(
            caller, "migrate_batch",
            results[0].key_id if results else "-",
            "total=%d migrated=%d already_current=%d failed=%d"
            % (len(results), counts["migrated"],
               counts["already_current"], counts["failed"]),
        )
        logger.info(
            "migrate_batch caller=%s total=%d migrated=%d already_current=%d failed=%d",
            caller, len(results), counts["migrated"],
            counts["already_current"], counts["failed"],
        )
        return MigrationBatchResult(items=results)

    def _migrate_one(
        self, caller: str, index: int, env: Envelope, counts: dict
    ) -> MigrationItemResult:
        if not isinstance(env, Envelope) or not env.key_id or env.key_version < 1:
            counts["failed"] += 1
            return MigrationItemResult(
                index=index, status=MigrationStatus.FAILED,
                key_id=getattr(env, "key_id", "") or "",
                source_version=getattr(env, "key_version", 0) or 0,
                target_version=None, envelope=None,
                error="malformed envelope",
            )
        fp = envelope_fingerprint(env)
        try:
            self._authorizer.check(caller, env.key_id, "migrate")
        except KeyManagementError as exc:
            counts["failed"] += 1
            return MigrationItemResult(
                index=index, status=MigrationStatus.FAILED,
                key_id=env.key_id, source_version=env.key_version,
                target_version=None, envelope=None,
                error=f"{exc.code}: {exc}",
            )

        active = self._keystore.get_active(env.key_id)
        if active is None:
            counts["failed"] += 1
            err = f"no active key version for {env.key_id!r}"
            self._record_failure(fp, env, err)
            return MigrationItemResult(
                index=index, status=MigrationStatus.FAILED,
                key_id=env.key_id, source_version=env.key_version,
                target_version=None, envelope=None, error=err,
            )

        # 本就处于当前活跃版本：无需任何密码学操作，幂等标记后原样返回
        if env.key_version == active.version:
            rec = self._migrations.mark_already_current(
                fp, env.key_id, env.key_version, env
            )
            counts["already_current"] += 1
            logger.info(
                "migrate item[%d] key=%s v%s already_current -> keep v%s",
                index, env.key_id, env.key_version, active.version,
            )
            return MigrationItemResult(
                index=index, status=rec.status, key_id=env.key_id,
                source_version=env.key_version, target_version=active.version,
                envelope=env,
            )

        rec = self._migrations.begin(fp, env.key_id, env.key_version)
        # 已成功（此前批次迁过）：直接回放登记的结果，不重复迁移
        if rec.status in (MigrationStatus.MIGRATED, MigrationStatus.ALREADY_CURRENT):
            counts["migrated"] += 1
            logger.info(
                "migrate item[%d] key=%s fingerprint=%s idempotent replay "
                "source=v%s target=v%s",
                index, env.key_id, fp[:12], env.key_version, rec.target_version,
            )
            return MigrationItemResult(
                index=index, status=rec.status, key_id=rec.key_id,
                source_version=rec.source_version, target_version=rec.target_version,
                envelope=rec.result,
            )

        try:
            source_kv = self._keystore.get_version(env.key_id, env.key_version)
            if source_kv is None:
                raise KeyNotFoundError(
                    f"key version not found: {env.key_id} v{env.key_version}"
                )
            if source_kv.status.value == "retired":
                raise KeyVersionRetiredError(
                    f"key version retired: {env.key_id} v{env.key_version}"
                )
            # 用源版本解出原文，再用当前 ACTIVE 版本重新封装；
            # 新信封结构与旧信封完全一致，调用方无感知。
            plaintext = self._cipher.decrypt(source_kv, env)
            new_env = self._cipher.encrypt(active, plaintext, env.aad)
            self._migrations.complete(fp, active.version, new_env)
            counts["migrated"] += 1
            logger.info(
                "migrate item[%d] key=%s source=v%s -> target=v%s attempt=%d "
                "判定依据: 源版本解密成功后以当前 ACTIVE 重封装",
                index, env.key_id, env.key_version, active.version, rec.attempts,
            )
            return MigrationItemResult(
                index=index, status=MigrationStatus.MIGRATED,
                key_id=env.key_id, source_version=env.key_version,
                target_version=active.version, envelope=new_env,
            )
        except KeyManagementError as exc:
            self._migrations.fail(fp, f"{exc.code}: {exc}")
            counts["failed"] += 1
            logger.info(
                "migrate item[%d] key=%s source=v%s failed attempt=%d reason=%s",
                index, env.key_id, env.key_version, rec.attempts, exc.code,
            )
            return MigrationItemResult(
                index=index, status=MigrationStatus.FAILED,
                key_id=env.key_id, source_version=env.key_version,
                target_version=None, envelope=None,
                error=f"{exc.code}: {exc}",
            )

    def _record_failure(self, fp: str, env: Envelope, error: str) -> None:
        """对未进入 begin 的失败项也留下登记，保证"上次迁移有未成功项"可被把关查到。"""
        rec = self._migrations.get(fp)
        if rec is not None and rec.status in (
            MigrationStatus.MIGRATED, MigrationStatus.ALREADY_CURRENT
        ):
            return
        self._migrations.begin(fp, env.key_id, env.key_version)
        self._migrations.fail(fp, error)

    # ------------------------------------------------------------------ 退役
    def retire_version(self, caller: str, key_id: str, version: int) -> None:
        """显式退役一个老版本（ARCHIVED -> RETIRED）。

        把关（任一不满足即以 RetirementBlockedError 拒绝，原因可区分）：
        1. 该版本作为源版本仍有 PENDING/PROCESSING/FAILED 的迁移项；
        2. 该 key 上还残留上一次迁移未成功的项（任何源版本）。
        已退役再次退役是幂等成功。
        """
        self._authorizer.check(caller, key_id, "retire")
        with self._migration_lock:
            kv = self._keystore.get_version(key_id, version)
            if kv is None:
                raise KeyNotFoundError(f"key version not found: {key_id} v{version}")
            if kv.status.value == "retired":
                logger.info("retire key=%s v%s already retired (idempotent)",
                            key_id, version)
                return
            pending = self._migrations.unfinished_count_for_source(key_id, version)
            if pending > 0:
                raise RetirementBlockedError(
                    f"cannot retire {key_id} v{version}: {pending} ciphertext(s) "
                    f"still not migrated off this version"
                )
            key_failures = self._migrations.unfinished_count_for_key(key_id)
            if key_failures > 0:
                raise RetirementBlockedError(
                    f"cannot retire {key_id} v{version}: {key_failures} migration "
                    f"item(s) for this key remain unsuccessful from the last batch"
                )
            if kv.status.value == "active":
                raise RetirementBlockedError(
                    f"cannot retire {key_id} v{version}: version is still ACTIVE; "
                    f"rotate before retiring"
                )
            self._keystore.retire(key_id, version)
        self._audit.append(caller, "retire_key", key_id,
                           f"version={version} status=retired "
                           f"判定依据: pending_for_version=0 unfinished_for_key=0")
        logger.info(
            "retire key=%s v%s approved: pending_for_version=0 unfinished_for_key=0",
            key_id, version,
        )


class KeyManagementConflictError(KeyManagementError):
    """密钥已存在等状态冲突。"""

    code = "key_conflict"
