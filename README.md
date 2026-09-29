# 本地信封加密、密钥轮换、历史密文迁移与版本退役

在本地模拟一套密钥托管/归档服务：主密钥按版本管理，支持创建、轮换、归档与**退役**；
业务数据用信封加密（AES-256-GCM）保护，密文自携带定位密钥版本所需的元数据；
支持把老版本密文**批量迁移**到当前活跃版本（幂等、可重试、中断可恢复）；
所有密钥状态变更写入可核验的审计链。

## 密钥版本模型

每个密钥（`key_id`）由一组单调递增的**版本**组成，每个版本处于三种状态之一：

| 状态 | 含义 |
|---|---|
| `ACTIVE` | 当前唯一可用于**新加密**的版本，每个 `key_id` 任一时刻恰好一个 |
| `ARCHIVED` | 历史版本，不再用于加密，但仍可用于**解密历史密文**与作为迁移源 |
| `RETIRED` | 已**退役**：既不可用于加密，也不可再用于解密；显式动作，不可逆 |

信封（`Envelope`）结构（迁移前后完全一致，调用方无需感知格式变化）：

```
Envelope = { key_id, key_version, iv, ciphertext, tag, aad }
```

`key_id + key_version` 即定位解密所需密钥版本的全部信息。

## 轮换规则

- `rotate_key` 在锁内原子完成：先把当前 `ACTIVE` 版本置为 `ARCHIVED`，再生成新版本并置为 `ACTIVE`。
- **不存在无可用版本的窗口**：任何时刻查询活跃版本都能命中。
- **轮换期间到达的并发加密**：加密请求先取到某个版本引用再执行加密。若取到的是轮换前的旧版本，该版本随后被归档保留，其密文仍可通过信封中的 `(key_id, key_version)` 定位并解密——不会产生无法解密的密文。
- **迁移与轮换并发**：迁移以批次提交时的当前 `ACTIVE` 为目标；批次之间发生轮换不影响正确性，不同批次可以落到不同目标版本，每个迁出的信封都能被解回原文。
- 历史版本归档后永不删除，直到被显式退役；因此未退役版本的历史密文始终可解密。

## 历史密文迁移

`migrate_batch(caller, envelopes)` 接收一批旧密文，逐件用其源版本解出原文，
再用当前 `ACTIVE` 版本以相同 AAD 重新封装，按提交原序返回每件的状态、源版本与目标版本。

- **幂等**：登记表以完整信封（版本/IV/密文/标签/AAD）的规范化 SHA-256 **指纹**为键。
  同一密文反复提交只做一次实际迁移，后续提交回放同一新信封——不重复迁、不弄坏已迁好的。
- **失败可重试**：单件失败（源版本不可用、完整性错误、越权等）标记为 `failed` 并附原因，
  同批其他件不受影响；修复后重新提交同一批即可继续。
- **已是当前版本**：标记为 `already_current`，不做任何密码学操作，原样返回。
- **结果可解释**：每件返回 `migrated` / `already_current` / `failed` 之一，
  汇总可直接回答"哪些迁了、迁到哪个版本、哪些还没成功"。
- **中断恢复**：状态在每件开始（`processing`）与完成（`migrated`）时落盘；
  进程崩溃/重启后，残留的 `processing` 回退为 `pending`，再次提交整批时
  已迁项回放、未完成项接着迁，不漏迁、不重迁。

> 把关以"已提交到迁移服务的登记项"为准：计划淘汰某版本前，请把该版本的存量密文
> 全部提交迁移；未提交、服务从未见过的密文无法被登记统计，也就不会被把关计数。

## 版本退役

`retire_version(caller, key_id, version)` 把一个 `ARCHIVED` 版本显式置为 `RETIRED`
（需 `rotate` 权限；`ACTIVE` 版本必须先轮换；重复退役幂等成功）。

退役前有两道把关，任一不满足即以 `retirement_blocked` 拒绝并给出原因：

1. 该版本作为迁移源仍有未成功项（`pending`/`processing`/`failed`）；
2. 该 `key_id` 上还残留上一次迁移未成功的项（任何源版本）。

退役生效后：

- 再用该版本解密，抛出 **`KeyVersionRetiredError`（`key_version_retired`）**，
  与"密钥/版本根本不存在"（`key_not_found`）、"调用方越权"
  （`authorization_error` / `key_scope_error`）明确可区分；
- 退役**之前**已迁到新版本的历史密文不受影响，照常解密。

## 完整性与篡改检测

加密时将 `key_id`、`key_version` 与调用方附加数据（AAD）一并编入 AES-GCM 的认证数据：

- 密文或认证标签被改动 → GCM 标签校验失败；
- 封装元数据（`key_id`/`key_version`）被改动 → 定位到错误密钥或 AAD 不匹配，校验失败；
- 解密时传入的 AAD 与加密时不一致 → 校验失败。

校验失败一律抛出 `IntegrityError`，**绝不返回错误明文**。迁移同样经过源版本的
完整性校验，被改过的密文无法通过迁移"洗白"。

## 错误分类

所有错误继承自 `KeyManagementError`，并携带稳定的 `code` 便于区分：

| 异常 | code | 触发场景 |
|---|---|---|
| `AuthorizationError` | `authorization_error` | 调用方未注册，或无该操作权限（如 rotate/retire/create） |
| `KeyScopeError` | `key_scope_error` | 调用方已认证，但目标密钥不在其授权范围内（`AuthorizationError` 子类，可单独捕获） |
| `KeyNotFoundError` | `key_not_found` | 信封引用的密钥版本不存在，或退役不存在的版本 |
| `KeyVersionRetiredError` | `key_version_retired` | 密钥版本存在但已退役，拒绝解密（区别于不存在与越权） |
| `RetirementBlockedError` | `retirement_blocked` | 仍有未迁完密文或上次迁移有失败项，或试图退役 ACTIVE 版本 |
| `NoActiveKeyError` | `no_active_key` | 密钥不存在或无 ACTIVE 版本时请求加密/迁移 |
| `IntegrityError` | `integrity_error` | 密文/标签/元数据/AAD 被篡改，完整性校验失败 |
| `EnvelopeFormatError` | `envelope_format_error` | 封装格式无法解析 |
| `KeyManagementConflictError` | `key_conflict` | 重复创建已存在的密钥 |

HTTP 层中授权类错误返回 403，其余返回 400，响应体均含 `code` 字段；
`/migrate` 整体返回 200，单件失败体现在每项的 `status`/`error` 中。

## 持久化与重启恢复

`KeyManagementService(state_dir=...)` 把以下状态以 JSON（临时文件 + 原子替换）
持久化到同一目录，进程重启后用该目录重建即恢复：

- 全部密钥版本材料与状态（含 `retired`）；
- 调用方授权注册表；
- 迁移登记表（指纹、状态、目标版本、新信封、尝试次数、上次错误）；
- 追加式审计链（恢复后新记录的前向哈希接续在最后一条之后，链不断裂）。

不传 `state_dir` 时为纯内存模式（测试默认）。

## 授权与审计

- 调用方（`Caller`）需预先注册，声明其可用的 `key_id` 集合及 `can_create`/`can_rotate`
  权限（退役复用 `can_rotate`）；越权请求在执行任何状态变更前被拒绝。
  迁移对每件信封逐项授权，单件越权不拖垮整批。
- 每次状态变更（`create_key`/`rotate_key`/`migrate_batch`/`retire_key`）追加一条
  `AuditRecord`：包含序号、时间戳、调用方、动作、详情及**前一条记录的哈希**，形成哈希链。
- `AuditLog.verify()` 可校验整条链的完整性；序号在锁内分配，并发调用后链仍自洽、序号连续。
- 被拒绝的越权/把关请求不产生密钥状态变更（退役的审计只在真正生效时写一条，
  幂等退役不重复写）。
- 服务日志（logger `kms`）记录轮换版本、每件迁移的源/目标版本与判定依据、
  退役把关的计数依据。

## 本地验证

```bash
# 安装依赖
uv sync

# 运行全部测试（迁移幂等/重试/崩溃恢复、退役把关与原因区分、迁移×轮换并发；
# 旧有的轮换/篡改/越权/并发用例同时保留，日志打印密钥版本与判定依据）
uv run pytest -q -o log_cli=true -o log_cli_level=INFO

# 启动 HTTP 服务
uv run uvicorn main:app --reload
```

HTTP 接口（调用方经 `x-caller` 头传入）：

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/keys` | 创建密钥，返回初始版本 1 |
| POST | `/keys/{key_id}/rotate` | 轮换，返回新的 ACTIVE 版本号 |
| POST | `/encrypt` | 信封加密，返回完整 Envelope（base64 字段） |
| POST | `/decrypt` | 按 Envelope 定位版本并解密（退役版本返回 `key_version_retired`） |
| POST | `/migrate` | 批量迁移旧密文到当前版本，逐件返回状态/源版本/目标版本/新信封 |
| POST | `/keys/{key_id}/versions/{version}/retire` | 显式退役一个老版本（把关不通过返回 `retirement_blocked`） |
| GET | `/audit/verify` | 校验审计哈希链 |

典型手工流程：

```bash
# 1) 用 v1 加密 -> 轮换到 v2
# 2) POST /migrate 提交 v1 老密文（可反复提交验证幂等）
# 3) POST /keys/orders/versions/1/retire 退役 v1
# 4) 再对 v1 密文调 /decrypt 得到 400 key_version_retired；
#    对迁移后的密文 /decrypt 仍得到原明文
```

## 目录结构

```
app/
  errors.py       # 错误分类（含 key_version_retired / retirement_blocked）
  models.py       # KeyVersion / Envelope / AuditRecord / 迁移状态与结果模型
  persistence.py  # JSON 原子写与状态目录
  keystore.py     # 本地密钥托管、归档、退役（线程安全，可持久化）
  crypto.py       # AES-256-GCM 信封加解密
  authz.py        # 调用方授权（线程安全，可持久化）
  audit.py        # 哈希链审计日志（线程安全，可持久化）
  migration.py    # 指纹键迁移登记表：幂等/重试/崩溃恢复
  service.py      # 门面：组合以上组件（create/rotate/encrypt/decrypt/migrate/retire）
main.py           # FastAPI HTTP 入口
tests/            # 冒烟 / 轮换 / 篡改 / 授权 / 并发 / 迁移 / 退役 测试
```
