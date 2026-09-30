"""密钥管理服务门面：组合存储、加密、迁移、授权与审计。

并发模型：一把可重入的状态锁（RLock）串行化所有状态变更
（create/rotate/retire/批次登记/逐项进度提交），保证：
- 轮换与迁移、加密、退役交错执行时，密钥状态、迁移进度、审计记录始终一致；
- 任一状态变更成功后立即原子持久化，中断重启后可从断点继续；
- 读路径（decrypt/get_active）无需独占状态锁，轮换在 keystore 锁内原子完成，
  不会出现无可用版本的窗口。
"""

from __future__ import annotations

import logging
import threading

from app.audit import AuditLog
from app.authz import Authorizer, Caller
from app.crypto import EnvelopeCipher
from app.errors import (
    EnvelopeFormatError,
    KeyManagementError,
    KeyNotFoundError,
    KeyRetiredError,
    NoActiveKeyError,
    RetirementBlockedError,
)
from app.keystore import LocalKeyStore
from app.migration import MigrationStore, validate_envelope_for_migration
from app.models import (
    Envelope,
    KeyStatus,
    MigrationItemResult,
    MigrationReport,
    MigrationStatus,
)
from app.persistence import JsonStateStore

logger = logging.getLogger("kms")


class KeyManagementService:
    """对外暴露 create/rotate/retire/encrypt/decrypt/migrate，状态变更均审计并持久化。"""

    def __init__(
        self,
        keystore: LocalKeyStore | None = None,
        cipher: EnvelopeCipher | None = None,
        authorizer: Authorizer | None = None,
        audit: AuditLog | None = None,
        migration_store: MigrationStore | None = None,
        state_store: JsonStateStore | None = None,
    ) -> None:
        self._state_lock = threading.RLock()
        self._state_store = state_store

        # 恢复或新建各组件：持久化模式下以文件快照为准
        restored: dict | None = None
        if state_store is not None and keystore is None:
            restored = state_store.load()
        if restored is not None:
            self._keystore = keystore or LocalKeyStore(restored.get("keystore"))
            self._audit = audit or AuditLog(restored.get("audit"))
            self._migration = migration_store or MigrationStore(restored.get("migrations"))
            # 调用方授权与密钥/迁移状态同文件落盘：重启后谁能做什么不变
            self._authorizer = authorizer or Authorizer(restored.get("authz"))
        else:
            self._keystore = keystore or LocalKeyStore()
            self._audit = audit or AuditLog()
            self._migration = migration_store or MigrationStore()
            self._authorizer = authorizer or Authorizer()
        self._cipher = cipher or EnvelopeCipher()

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
    def migration_store(self) -> MigrationStore:
        return self._migration

    def _persist(self) -> None:
        """在状态锁内调用：把四部分状态原子落盘。"""
        if self._state_store is not None:
            self._state_store.save(
                self._keystore.snapshot(),
                self._migration.snapshot(),
                self._audit.snapshot(),
                self._authorizer.snapshot(),
            )

    def register_caller(self, caller: Caller) -> None:
        """登记（或更新）调用方授权，并随状态快照一起持久化。

        持久化模式下重启无需重新登记：可用密钥范围与操作权限原样恢复。
        """
        with self._state_lock:
            self._authorizer.register(caller)
            self._persist()
        logger.info(
            "register_caller caller=%s keys=%s can_create=%s can_rotate=%s",
            caller.name, sorted(caller.allowed_key_ids),
            caller.can_create, caller.can_rotate,
        )

    # ---- 生命周期管理 ----

    def create_key(self, caller: str, key_id: str) -> int:
        self._authorizer.check(caller, key_id, "create")
        with self._state_lock:
            try:
                kv = self._keystore.create_key(key_id)
            except ValueError as exc:
                raise KeyManagementConflictError(str(exc)) from exc
            self._audit.append(caller, "create_key", key_id,
                               f"version={kv.version} status=active")
            self._persist()
        logger.info("create_key caller=%s key=%s version=%d", caller, key_id, kv.version)
        return kv.version

    def rotate_key(self, caller: str, key_id: str) -> int:
        self._authorizer.check(caller, key_id, "rotate")
        with self._state_lock:
            try:
                kv = self._keystore.rotate(key_id)
            except KeyError as exc:
                raise KeyNotFoundError(f"unknown key: {key_id}") from exc
            self._audit.append(caller, "rotate_key", key_id,
                               f"new_active_version={kv.version} previous_archived")
            self._persist()
        logger.info(
            "rotate_key caller=%s key=%s new_active_version=%d (旧版本保留可解密)",
            caller, key_id, kv.version,
        )
        return kv.version

    def retire_key(self, caller: str, key_id: str, version: int) -> int:
        """显式退役一个非 ACTIVE 版本；退役后该版本解密被 KeyRetiredError 拒绝。

        把关：该版本仍有 PENDING/FAILED 的迁移项时拒绝退役。
        对已经是 RETIRED 的版本重复调用是幂等的，直接返回该版本号。
        """
        self._authorizer.check(caller, key_id, "retire")
        with self._state_lock:
            kv = self._keystore.get_version(key_id, version)
            if kv is None:
                logger.info("retire_key 拒绝: caller=%s key=%s v%d 原因=版本不存在",
                            caller, key_id, version)
                raise KeyNotFoundError(
                    f"key version not found: {key_id} v{version}")
            if kv.status is KeyStatus.RETIRED:
                logger.info("retire_key 幂等返回: key=%s v%d 已处于 retired",
                            key_id, version)
                return version
            if kv.status is KeyStatus.ACTIVE:
                raise RetirementBlockedError(
                    f"cannot retire the active version: {key_id} v{version}; "
                    f"rotate to a newer version first"
                )
            # 把关按整把密钥判定：只要该 key_id 还有任一历史数据项（无论来自哪个
            # 版本、属于哪个批次）没迁成功，任何归档版本都不能退役。
            outstanding = self._migration.outstanding_summary(key_id)
            if outstanding:
                detail = ", ".join(
                    f"batch={bid} item={fp[:12]} source_version={sv} status={st}"
                    for bid, fp, sv, st in outstanding
                )
                logger.info(
                    "retire_key 拒绝: caller=%s key=%s v%d 原因=该密钥尚有 %d 项未迁成功 "
                    "(跨全部版本/批次) (%s)",
                    caller, key_id, version, len(outstanding), detail,
                )
                raise RetirementBlockedError(
                    f"version {version} of key {key_id!r} cannot be retired: "
                    f"{len(outstanding)} ciphertext item(s) on this key (across any "
                    f"version/batch) are not migrated successfully yet (pending/failed); "
                    f"detail=[{detail}]"
                )
            retired = self._keystore.retire(key_id, version)
            self._audit.append(caller, "retire_key", key_id,
                               f"version={retired.version} status=retired "
                               f"outstanding_on_key_at_retirement=0")
            self._persist()
        logger.info(
            "retire_key 完成: caller=%s key=%s v%d 判定依据=该密钥全部版本无未成功迁移项, "
            "此后该版本解密将拒绝",
            caller, key_id, version,
        )
        return retired.version

    # ---- 信封加解密 ----

    def encrypt(self, caller: str, key_id: str, plaintext: bytes, aad: bytes = b"") -> Envelope:
        self._authorizer.check(caller, key_id, "encrypt")
        kv = self._keystore.get_active(key_id)
        if kv is None:
            raise NoActiveKeyError(f"no active key version for {key_id!r}")
        # 在取到的版本上完成加密：即使此刻发生轮换，该版本已被归档保留，
        # 密文仍可通过信封中的 (key_id, version) 定位并解密。
        env = self._cipher.encrypt(kv, plaintext, aad)
        logger.info("encrypt caller=%s key=%s 使用版本=%d", caller, key_id, kv.version)
        return env

    def decrypt(self, caller: str, envelope: Envelope, aad: bytes = b"") -> bytes:
        if not isinstance(envelope, Envelope) or not envelope.key_id or envelope.key_version < 1:
            raise EnvelopeFormatError("malformed envelope")
        self._authorizer.check(caller, envelope.key_id, "decrypt")
        kv = self._keystore.get_version(envelope.key_id, envelope.key_version)
        if kv is None:
            logger.info("decrypt 拒绝: caller=%s key=%s v%d 原因=版本不存在",
                        caller, envelope.key_id, envelope.key_version)
            raise KeyNotFoundError(
                f"key version not found: {envelope.key_id} v{envelope.key_version}"
            )
        if kv.status is KeyStatus.RETIRED:
            # 与"版本不存在"（KeyNotFoundError）、"越权"（AuthorizationError）明确区分
            logger.info("decrypt 拒绝: caller=%s key=%s v%d 原因=版本已退役",
                        caller, envelope.key_id, envelope.key_version)
            raise KeyRetiredError(
                f"key version retired: {envelope.key_id} v{envelope.key_version}; "
                f"ciphertext must be re-encrypted to a current version before decrypting"
            )
        plaintext = self._cipher.decrypt(kv, envelope, aad)
        logger.info("decrypt 成功: caller=%s key=%s v%d status=%s",
                    caller, envelope.key_id, envelope.key_version, kv.status.value)
        return plaintext

    # ---- 历史数据迁移 ----

    def migrate_batch(
        self,
        caller: str,
        key_id: str,
        envelopes: list[Envelope],
        batch_id: str,
    ) -> MigrationReport:
        """把一批旧密文重新加密到当前活跃版本。

        幂等：batch_id + 密文指纹集合唯一标识一次迁移；重复提交同一批时
        - 已迁好/本就活跃的项原样返回，绝不二次迁移；
        - PENDING/FAILED 的项继续推进；
        - 提交集合与首次不一致直接拒绝（MigrationBatchMismatchError）。
        每处理完一项立即持久化，中断/重启后用同一 batch_id 重试即可接着迁。
        """
        self._authorizer.check(caller, key_id, "migrate")
        if not envelopes:
            raise EnvelopeFormatError("migration batch is empty")

        # 先整批做结构校验，再进入锁登记批次：任何一个元素不是合法信封
        # （类型不对/结构不完整/key_id 对不上）都以可区分的 envelope_format_error
        # 整体拒绝，不登记批次、不产生任何状态变更，更不会冒出内部异常。
        for idx, raw in enumerate(envelopes):
            validate_envelope_for_migration(raw, idx, key_id)

        with self._state_lock:
            batch, created = self._migration.register_or_get(batch_id, key_id, envelopes)
            if created:
                self._audit.append(
                    caller, "migration_register", key_id,
                    f"batch={batch_id} items={len(batch.order)}",
                )
                self._persist()
            active = self._keystore.get_active(key_id)
            if active is None:
                raise NoActiveKeyError(f"no active key version for {key_id!r}")
            active_version = active.version

            results: list[MigrationItemResult] = []
            counts = {"migrated": 0, "already_current": 0, "failed": 0,
                      "pending": 0, "skipped": 0}
            for fp in batch.order:
                item = batch.items[fp]
                if item.status in (MigrationStatus.MIGRATED, MigrationStatus.ALREADY_CURRENT):
                    # 已成功的项：重复提交不重复迁，直接还回上次结果
                    counts["skipped"] += 1
                    results.append(self._item_result(item))
                    continue

                # 该来源版本若已退役，本批次无法解密，记为失败并给出明确原因，
                # 不影响同批其它项继续迁移。
                source_kv = self._keystore.get_version(key_id, item.source_version)
                if source_kv is None:
                    self._migration.mark_failed(
                        item, f"source version not found: v{item.source_version}")
                    self._persist()
                    counts["failed"] += 1
                    results.append(self._item_result(item))
                    continue
                if source_kv.status is KeyStatus.RETIRED:
                    self._migration.mark_failed(
                        item, f"source version retired: v{item.source_version}")
                    self._persist()
                    counts["failed"] += 1
                    results.append(self._item_result(item))
                    continue

                # 活跃版本判定以本批次提交时刻的 ACTIVE 为准；
                # 已被轮换归档的"迁移目标"仍可解密，迁移结果持续有效。
                if item.source_version == active_version:
                    self._migration.mark_already_current(item, active_version)
                    self._persist()
                    counts["already_current"] += 1
                    results.append(self._item_result(item))
                    continue

                self._migration.record_attempt(item)
                try:
                    plaintext = self._cipher.decrypt(source_kv, item.source)
                    target_env = self._cipher.encrypt(active, plaintext, item.source.aad)
                except KeyManagementError as exc:
                    self._migration.mark_failed(item, f"{exc.code}: {exc}")
                    self._persist()
                    counts["failed"] += 1
                    logger.info(
                        "migrate 单项失败: key=%s batch=%s item=%s v%d -> v%d 原因=%s",
                        key_id, batch_id, fp[:12], item.source_version,
                        active_version, exc.code,
                    )
                    results.append(self._item_result(item))
                    continue
                self._migration.mark_migrated(item, active_version, target_env)
                self._persist()
                counts["migrated"] += 1
                results.append(self._item_result(item))

            report = MigrationReport(
                batch_id=batch_id, key_id=key_id,
                active_version=active_version, items=results,
            )
            self._audit.append(
                caller, "migration_complete", key_id,
                f"batch={batch_id} active_version={active_version} "
                f"migrated={counts['migrated']} already_current={counts['already_current']} "
                f"skipped={counts['skipped']} failed={counts['failed']} "
                f"complete={report.complete}",
            )
            self._persist()

        logger.info(
            "migrate_batch 完成: caller=%s key=%s batch=%s 判定依据=目标活跃版本 v%d "
            "新迁=%d 本就活跃=%d 幂等跳过=%d 失败=%d 整体完成=%s",
            caller, key_id, batch_id, active_version,
            counts["migrated"], counts["already_current"],
            counts["skipped"], counts["failed"], report.complete,
        )
        return report

    @staticmethod
    def _item_result(item) -> MigrationItemResult:
        return MigrationItemResult(
            index=item.index,
            fingerprint=item.fingerprint,
            source_version=item.source_version,
            status=item.status,
            target_version=item.target_version,
            envelope=item.target,
            error=item.error,
        )


class KeyManagementConflictError(KeyManagementError):
    """密钥已存在等状态冲突。"""

    code = "key_conflict"
