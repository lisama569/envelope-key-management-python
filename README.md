# 本地信封加密、密钥轮换、历史迁移与版本退役

在本地模拟一套密钥托管/归档/退役服务：主密钥按版本管理，支持创建、轮换、归档与退役；
业务数据用信封加密（AES-256-GCM）保护，密文自携带定位密钥版本所需的元数据；
历史密文可幂等批量迁移到当前活跃版本；迁移/退役/密钥状态可落盘，重启后从断点继续；
所有密钥状态变更写入可核验的审计链。

## 密钥版本模型

每个密钥（`key_id`）由一组单调递增的**版本**组成，每个版本处于三种状态之一：

| 状态 | 含义 |
|---|---|
| `ACTIVE` | 当前唯一可用于**新加密**的版本，每个 `key_id` 任一时刻恰好一个 |
| `ARCHIVED` | 历史版本，不再用于加密，但保留用于**解密或迁移历史密文**，等待退役 |
| `RETIRED` | 已显式退役：既不能加密，也**不能再用于解密**（与"版本不存在"明确区分） |

信封（`Envelope`）结构在迁移前后保持不变：

```
Envelope = { key_id, key_version, iv, ciphertext, tag, aad }
```

`key_id + key_version` 即定位解密所需密钥版本的全部信息。迁移只换 IV/密文/标签/版本号，
字段集合与编码方式不变，调用方拿到的仍然是同一种信封。

## 轮换规则

- `rotate_key` 在锁内原子完成：先把当前 `ACTIVE` 版本置为 `ARCHIVED`，再生成新版本并置为 `ACTIVE`。
- **不存在无可用版本的窗口**：任何时刻查询活跃版本都能命中。
- **轮换期间到达的并发加密**：加密请求先取到某个版本引用再执行加密。若取到的是轮换前的旧版本，该版本随后轮换后被归档保留，其密文仍可通过信封中的 `(key_id, key_version)` 定位并解密——不会产生无法解密的密文。
- 历史版本永不删除，因此历史密文始终可解密——除非该版本被**显式退役**（见下）。

## 历史数据迁移（re-encrypt to current version）

`migrate_batch(caller, key_id, envelopes, batch_id)` 把调用方提交的一批旧密文
解密后用**批次提交时刻的活跃版本**重新加密，返回 `MigrationReport`。

幂等与断点续传规则：

- **批次身份** = 调用方给定的 `batch_id` + 全部信封字段的 SHA-256 指纹集合
  （指纹覆盖 `key_id/版本/IV/密文/标签/AAD`，任一字节不同即为不同项）。
- 同一 `batch_id` 反复提交同一批密文：
  - 已迁好（`MIGRATED`）或本就活跃（`ALREADY_CURRENT`）的项**原样返回，绝不二次迁移**，
    因此重复提交不会把已迁好的数据弄坏；
  - 未成功（`PENDING`/`FAILED`，如解密超时、篡改、来源版本已退役）的项继续推进，
    不漏迁；
  - 每处理完一项立即原子落盘，进程被杀死/重启后用同一 `batch_id` 再交即可从断点继续。
- 同一 `batch_id` 但密文集合与首次不一致 → `MigrationBatchMismatchError`（防串号、防漏项）。
- 报告逐项给出：批次内序号、指纹、来源版本、状态、目标版本、迁移后信封与失败原因；
  `complete=True` 当且仅当没有 `PENDING/FAILED` 项。

迁移目标版本在登记时确定；即便批次处理期间发生轮换，旧目标只是从 ACTIVE 变为
ARCHIVED，迁移结果仍然有效、可解密。已用活跃版本加密的项标记为 `ALREADY_CURRENT`，
不重新加密（不换 IV）。

## 版本退役（retire）

`retire_key(caller, key_id, version)` 把一个 `ARCHIVED` 版本显式标记为 `RETIRED`。

- 退役需要与轮换同级的权限（`can_rotate`）；不能退役当前 `ACTIVE` 版本（先轮换再退役）。
- **退役把关**：该版本在任一登记批次中仍有 `PENDING/FAILED` 的迁移项时，拒绝退役
  （`RetirementBlockedError`），错误信息列出具体批次、项指纹与状态；全部迁完才放行。
- 退役是幂等的：对已 `RETIRED` 的版本重复调用直接返回，不重复写审计。
- 退役后再用该版本解密，抛出 **`KeyRetiredError`（`key_retired`）**——与
  "版本根本不存在"的 `KeyNotFoundError`（`key_not_found`）和"调用方越权"的
  `AuthorizationError`/`KeyScopeError`（`authorization_error`/`key_scope_error`）
  三者可明确区分；授权校验先于退役状态校验。
- **退役不影响已迁数据**：退役前已重新加密到活跃版本的历史密文照样能解，
  新版本的加密/解密也不受影响。

## 并发一致性与重启恢复

- 服务内一把可重入状态锁串行化全部状态变更（轮换/退役/批次登记/逐项进度/审计追加），
  轮换仍在 keystore 锁内原子完成，因此迁移与轮换、加密、解密并发时：
  不产生解不开的密文，不出现无 `ACTIVE` 版本的窗口，退役状态与迁移进度始终对得上。
- 逐项迁移"先解密重加密、再 CAS 落状态"：重复/并发提交已成功的项不会被二次迁移。
- 设置 `KMS_STATE_FILE`（或构造 `JsonStateStore`）后，密钥版本、退役状态、
  迁移批次进度与审计链写入**同一个 JSON 文件**，写入为"临时文件 + fsync + 原子替换"，
  任意时刻崩溃只会停留在上一份完整快照；重启后恢复，批次可从断点继续迁移，
  退役状态与审计哈希链仍可解释、可续验。

## 完整性与篡改检测

加密时将 `key_id`、`key_version` 与调用方附加数据（AAD）一并编入 AES-GCM 的认证数据：

- 密文或认证标签被改动 → GCM 标签校验失败；
- 封装元数据（`key_id`/`key_version`）被改动 → 定位到错误密钥或 AAD 不匹配，校验失败；
- 解密时传入的 AAD 与加密时不一致 → 校验失败。

校验失败一律抛出 `IntegrityError`，**绝不返回错误明文**。

## 错误分类

所有错误继承自 `KeyManagementError`，并携带稳定的 `code` 便于区分：

| 异常 | code | 触发场景 |
|---|---|---|
| `AuthorizationError` | `authorization_error` | 调用方未注册，或无该操作权限（如 rotate/create） |
| `KeyScopeError` | `key_scope_error` | 调用方已认证，但目标密钥不在其授权范围内（`AuthorizationError` 子类，可单独捕获） |
| `KeyNotFoundError` | `key_not_found` | 信封引用的密钥版本不存在，或退役一个不存在的版本 |
| `KeyRetiredError` | `key_retired` | 信封引用的版本已**显式退役**，需先迁移到当前版本 |
| `RetirementBlockedError` | `retirement_blocked` | 退役被拦：该版本仍有未迁完（PENDING/FAILED）的密文，或试图退役 ACTIVE 版本 |
| `MigrationBatchMismatchError` | `migration_batch_mismatch` | 同一 `batch_id` 重试时提交的密文集合与首次不一致 |
| `NoActiveKeyError` | `no_active_key` | 密钥不存在或无 ACTIVE 版本时请求加密/迁移 |
| `IntegrityError` | `integrity_error` | 密文/标签/元数据/AAD 被篡改，完整性校验失败（迁移时该项记为 FAILED） |
| `EnvelopeFormatError` | `envelope_format_error` | 封装格式无法解析，或迁移批次为空 |
| `KeyManagementConflictError` | `key_conflict` | 重复创建已存在的密钥 |

HTTP 层状态码：授权类 403，`key_not_found` 为 404，冲突类
（`key_conflict`/`migration_batch_mismatch`）为 409，
其余（含 `key_retired`/`retirement_blocked`）为 400；响应体均含 `code` 字段。

## 授权与审计

- 调用方（`Caller`）需预先注册，声明其可用的 `key_id` 集合及 `can_create`/`can_rotate` 权限；越权请求在执行任何状态变更前被拒绝。
- 每次密钥状态变更（`create_key`/`rotate_key`/`retire_key`/迁移登记/迁移完成）追加一条
  `AuditRecord`：包含序号、时间戳、调用方、动作、详情及**前一条记录的哈希**，形成哈希链。
  迁移完成记录含目标活跃版本与 migrated/already_current/skipped/failed/complete 计数。
- `AuditLog.verify()` 可校验整条链的完整性（无插入、删除、篡改）；序号在锁内分配，并发调用后链仍自洽、序号连续；快照恢复后链可继续追加并校验。
- 被拒绝的越权请求不产生状态变更，也不写入审计记录，密钥状态与审计记录始终可相互解释。

## 与老数据的兼容范围

- 老密文（轮换前版本加密）在其版本处于 `ACTIVE/ARCHIVED` 时始终可解，行为与上一版一致。
- 迁移后的密文仍是同一个 `Envelope` 结构（字段集合、base64 编码、AAD 语义均不变），
  调用方无需感知格式变化；仅 `key_version` 更新为活跃版本。
- 仅当老版本被**显式退役**后，未迁移的老密文才无法直接解密（`key_retired`），
  这是合规要求的有意行为；已迁移密文不受影响。
- 服务无状态文件时完全等价于上一版的纯内存行为；旧代码构造的各组件仍可直接注入使用。

## 本地验证

```bash
# 安装依赖
uv sync

# 运行全部测试（含轮换、篡改、越权、迁移幂等/重试、退役把关、
# 迁移×轮换并发、重启断点续迁；日志打印密钥版本与判定依据）
uv run pytest -q -o log_cli=true -o log_cli_level=INFO

# 启动 HTTP 服务（默认纯内存；设置 KMS_STATE_FILE 后状态落盘、重启可恢复）
KMS_STATE_FILE=./kms-state.json uv run uvicorn main:app --reload
```

HTTP 接口（调用方经 `x-caller` 头传入）：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/keys` | 创建密钥，返回初始版本 1 |
| POST | `/keys/{key_id}/rotate` | 轮换，返回新的 ACTIVE 版本号 |
| POST | `/keys/{key_id}/versions/{version}/retire` | 退役指定版本；有未迁完项时返回 `retirement_blocked` |
| POST | `/keys/{key_id}/migrate` | 幂等批量迁移；请求体含 `batch_id` 与信封数组，返回逐项状态/目标版本/迁移后信封 |
| POST | `/encrypt` | 信封加密，返回完整 Envelope（base64 字段） |
| POST | `/decrypt` | 按 Envelope 定位版本并解密；退役版本返回 `key_retired` |
| GET | `/audit/verify` | 校验审计哈希链 |

手工冒烟：先 `/encrypt` 得到 v1 信封，`/rotate` 后用原信封调 `/migrate`（同一
`batch_id` 可重复提交验证幂等），再 `retire` v1，之后用原 v1 信封 `/decrypt`
得到 `key_retired`，用迁移返回的新信封 `/decrypt` 仍得到原文。

## 目录结构

```
app/
  errors.py       # 错误分类（含 key_retired / retirement_blocked / migration_*）
  models.py       # KeyVersion / Envelope / AuditRecord / 迁移报告模型
  keystore.py     # 本地密钥托管、归档、退役、快照（线程安全）
  crypto.py       # AES-256-GCM 信封加解密
  migration.py    # 迁移批次/逐项进度、指纹幂等、快照
  persistence.py  # JSON 原子快照持久化（重启恢复）
  authz.py        # 调用方授权
  audit.py        # 哈希链审计日志（支持快照）
  service.py      # 门面：状态锁 + 组合以上组件
main.py           # FastAPI HTTP 入口
tests/            # 轮换 / 篡改 / 授权 / 并发 / 迁移 / 退役 测试
```
