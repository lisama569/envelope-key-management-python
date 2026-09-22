# 本地信封加密与密钥轮换

在本地模拟一套密钥托管/归档服务：主密钥按版本管理，支持创建、轮换与归档；
业务数据用信封加密（AES-256-GCM）保护，密文自携带定位密钥版本所需的元数据；
所有密钥状态变更写入可核验的审计链。

## 密钥版本模型

每个密钥（`key_id`）由一组单调递增的**版本**组成，每个版本处于两种状态之一：

| 状态 | 含义 |
|---|---|
| `ACTIVE` | 当前唯一可用于**新加密**的版本，每个 `key_id` 任一时刻恰好一个 |
| `ARCHIVED` | 历史版本，不再用于加密，但永久保留用于**解密历史密文** |

信封（`Envelope`）结构：

```
Envelope = { key_id, key_version, iv, ciphertext, tag, aad }
```

`key_id + key_version` 即定位解密所需密钥版本的全部信息。

## 轮换规则

- `rotate_key` 在锁内原子完成：先把当前 `ACTIVE` 版本置为 `ARCHIVED`，再生成新版本并置为 `ACTIVE`。
- **不存在无可用版本的窗口**：任何时刻查询活跃版本都能命中。
- **轮换期间到达的并发加密**：加密请求先取到某个版本引用再执行加密。若取到的是轮换前的旧版本，该版本随后轮换后被归档保留，其密文仍可通过信封中的 `(key_id, key_version)` 定位并解密——不会产生无法解密的密文。
- 历史版本永不删除，因此历史密文始终可解密。

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
| `KeyNotFoundError` | `key_not_found` | 信封引用的密钥版本不存在 |
| `NoActiveKeyError` | `no_active_key` | 密钥不存在或无 ACTIVE 版本时请求加密 |
| `IntegrityError` | `integrity_error` | 密文/标签/元数据/AAD 被篡改，完整性校验失败 |
| `EnvelopeFormatError` | `envelope_format_error` | 封装格式无法解析 |
| `KeyManagementConflictError` | `key_conflict` | 重复创建已存在的密钥 |

HTTP 层中授权类错误返回 403，其余返回 400，响应体均含 `code` 字段。

## 授权与审计

- 调用方（`Caller`）需预先注册，声明其可用的 `key_id` 集合及 `can_create`/`can_rotate` 权限；越权请求在执行任何状态变更前被拒绝。
- 每次密钥状态变更（`create_key`/`rotate_key`）追加一条 `AuditRecord`：包含序号、时间戳、调用方、动作、详情及**前一条记录的哈希**，形成哈希链。
- `AuditLog.verify()` 可校验整条链的完整性（无插入、删除、篡改）；序号在锁内分配，并发调用后链仍自洽、序号连续。
- 被拒绝的越权请求不产生状态变更，也不写入审计记录，密钥状态与审计记录始终可相互解释。

## 本地验证

```bash
# 安装依赖
uv sync

# 运行全部测试（含轮换、篡改、越权、并发场景；日志打印密钥版本与判定依据）
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
| POST | `/decrypt` | 按 Envelope 定位版本并解密 |
| GET | `/audit/verify` | 校验审计哈希链 |

## 目录结构

```
app/
  errors.py    # 错误分类
  models.py    # KeyVersion / Envelope / AuditRecord
  keystore.py  # 本地密钥托管与归档（线程安全）
  crypto.py    # AES-256-GCM 信封加解密
  authz.py     # 调用方授权
  audit.py     # 哈希链审计日志
  service.py   # 门面：组合以上组件
main.py        # FastAPI HTTP 入口
tests/         # 轮换 / 篡改 / 授权 / 并发测试
```
