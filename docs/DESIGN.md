# 本地信封加密与密钥轮换设计

本服务用**本地文件存储**模拟密钥托管服务（KMS）与密钥归档，实现：

- 主密钥（CMK）的创建、轮换、版本归档；
- 信封加密（Envelope Encryption）与三层完整性校验；
- 按调用方区分的操作授权与密钥范围授权；
- 仅追加、带哈希链的可核验审计。

## 1. 密钥版本模型

- 每个逻辑密钥有一个 `key_id`，其下有若干不可变版本，版本号从 `1` 开始单调递增。
- **任一时刻只有一个版本（`current_version`）用于新加密**；所有历史版本永久保留，仅用于解密。
- 每个版本独立生成 32 字节主密钥根（master secret），版本密钥由 HKDF-SHA256 派生：

  ```
  version_key = HKDF(master_secret_vn, info="version-key:<key_id>:<n>")
  ```

  不同版本、不同 key_id 的密钥在密码学上相互隔离。
- 持久化文件：`data/ekm/keys.json`。每个版本的密钥根一经写入永不修改；
  落盘使用「临时文件 + fsync + 原子替换」，避免半写损坏。

```jsonc
{
  "k1": {
    "key_id": "k1",
    "current_version": 2,        // 新加密唯一使用版本
    "created_at": "2026-09-22T00:00:00+00:00",
    "master_secrets": { "1": "<b64>", "2": "<b64>" }  // 版本归档，永不删除
  }
}
```

## 2. 轮换规则与并发正确性

一次轮换在**同一把全局锁**内原子完成四步：

1. 生成新版本密钥根并归档（旧版本保留）；
2. 全量持久化（崩溃后新版本也已可用）；
3. 切换 `current_version = n+1`（一次原子赋值）；
4. 追加 `key.rotate` 审计记录。

由此得到的保证：

- **无「无可用版本」窗口**：v1 在创建时即就绪；状态跃迁对外要么是旧版本、要么是已完全就绪的新版本。
- **轮换瞬间的密文不会无法解密**：加密只在锁内读取 `current_version` 的**快照**，
  然后使用该（已归档、不可变）版本密钥在锁外计算。即使在计算期间发生轮换，
  所用版本也已永久归档，密文永久可解密。
- **历史密文可解密**：解密不看 `current_version`，而是按信封内的 `key_id/key_version`
  定位归档版本；任意次轮换后旧密文照常解密。
- **幂等轮换**：携带相同 `idempotency_key` 的重试/并发调用只产生一个新版本、一条审计，
  返回同一结果；幂等键若绑定到不同请求则返回 `EKM_IDEMPOTENCY_CONFLICT`。
- 注意：不带幂等键的轮换是**有意的状态变更**，重复调用会产生新版本（审计可逐条解释）。

## 3. 信封结构与完整性校验

加密时生成随机数据加密密钥 DEK（32B），结构如下（JSON 字段均为 base64）：

| 字段 | 含义 |
|---|---|
| `envelope_version` | 信封格式版本（当前 1） |
| `key_id` / `key_version` | **定位解密所需密钥版本** |
| `iv` | 数据 GCM 的 12B nonce |
| `wrapped_dek` | `nonce(12) ‖ AES-256-GCM(wrap_key, DEK, AAD=规范头部)` |
| `ciphertext` | `AES-256-GCM(DEK, iv, plaintext, AAD=调用方AAD) ‖ tag` |
| `aad` | 附加数据原文（base64） |
| `hat` | 头部标签 `HMAC-SHA256(hat_key, 规范头部)` |
| `aat` | AAD 标签 `HMAC-SHA256(aat_key, aad)`，`aat_key=HKDF(DEK, "aat-key")` |

`wrap_key`、`hat_key` 均由 `version_key` 经 HKDF 以不同 info 派生，密钥相互独立。

**解密按固定顺序做四层校验，篡改原因可区分，且任何一层失败都不会返回明文：**

1. **头部 HAT**：校验 `envelope_version/key_id/key_version`；
2. **解封装 DEK**：GCM 以规范头部为 AAD，`wrapped_dek` 或头部不一致即失败；
3. **AAD / AAT**：先可选比对调用方 `expected_aad`，再用 DEK 派生密钥校验 AAT；
4. **数据 GCM**：校验密文、nonce 与标签。

> 设计要点：`hat` 只覆盖头部（不含 aad/ciphertext），`aat` 密钥派生自解封装后的 DEK，
> 因此「改元数据 / 改 AAD / 改密文」分别在不同层、用不同密钥被发现，错误互不混淆。

## 4. 错误分类

所有错误返回 `{"error": {"code", "message", "details"}}`，`code` 稳定可用于分支处理。

| code | HTTP | 触发场景 |
|---|---|---|
| `EKM_UNAUTHENTICATED` | 401 | 缺少 `X-Actor`，或身份未知（`details.reason=MISSING_IDENTITY/UNKNOWN_IDENTITY`） |
| `EKM_FORBIDDEN` | 403 | 已认证但越权：`ACTION_DENIED`（无该操作权限）或 `KEY_SCOPE_DENIED`（密钥不在授权范围） |
| `EKM_KEY_ALREADY_EXISTS` | 409 | 重复创建同名密钥 |
| `EKM_IDEMPOTENCY_CONFLICT` | 409 | 幂等键绑定了不同请求 |
| `EKM_KEY_VERSION_NOT_FOUND` | 404 | 密钥/版本不存在（含信封指向不存在版本） |
| `EKM_MALFORMED_ENVELOPE` | 400 | 信封缺字段、类型错误、base64/格式损坏 |
| `EKM_METADATA_TAMPERED` | 400 | **元数据篡改**：HAT 失败，或 wrapped_dek 解封装失败 |
| `EKM_AAD_TAMPERED` | 400 | **附加数据篡改**：AAT 失败或 `expected_aad` 不一致 |
| `EKM_CIPHERTEXT_TAMPERED` | 400 | **密文篡改**：数据 GCM 认证失败（ciphertext/iv/tag） |
| `EKM_AUDIT_VERIFICATION_FAILED` | 500 | 审计哈希链断裂或记录被改写 |

授权先于密钥存在性检查，避免向越权方泄露「密钥是否存在」。

## 5. 调用方授权模型（本地模拟 IAM）

身份由 `X-Actor` 头携带。预置策略：

| 调用方 | 允许动作 | 密钥范围 |
|---|---|---|
| `admin` | 全部（创建/轮换/读/加解密/审计核验） | 全部 |
| `crypto-a` | encrypt, decrypt | `k1`, `k2` |
| `crypto-b` | encrypt, decrypt | `k3` |
| `auditor` | key.read | 全部 |

`key_scope` 为空集合表示不限密钥。动作越权与密钥范围越权分别给出
`ACTION_DENIED` / `KEY_SCOPE_DENIED`，拒绝事件也写入审计。

## 6. 审计链

文件：`data/ekm/audit.jsonl`（仅追加 JSONL）。每条记录：

```
entry_hash = SHA256(prev_hash ‖ canonical(seq,timestamp,action,actor,key_id,key_version,detail,prev_hash))
```

首条 `prev_hash = GENESIS`。任意插入、删除、改写都会让链断裂，
`GET /audit/verify`（仅 admin）或 `service.audit.verify()` 会重算全链并发现。
记录的状态变更事件：`key.create`、`key.rotate`、`authz.deny`。

## 7. 目录与模块

```
ekm/
  errors.py    错误分类（稳定 code + HTTP 状态）
  crypto.py    HKDF 派生、DEK 封装、四层完整性校验
  storage.py   keys.json 原子持久化（版本归档）
  audit.py     哈希链审计
  authz.py     身份认证、动作与密钥范围授权
  service.py   线程安全编排（锁、轮换、加解密、幂等、审计）
  api.py       FastAPI 端点与错误映射
main.py        uvicorn 入口
tests/         单元/并发/边界/API 测试
```

## 8. 本地验证方法

```bash
# 环境
uv sync

# 全量测试（含轮换并发、历史解密、三类篡改、越权）
uv run pytest

# 查看单测中打印的「所用密钥版本 + 判定依据」
uv run pytest -o log_cli=true -o log_cli_level=INFO

# 启动服务
uv run uvicorn main:app --reload
```

### curl 速查

```bash
# 创建 / 轮换（幂等键可选）
curl -s -X POST localhost:8000/keys -H 'X-Actor: admin' \
  -H 'Content-Type: application/json' -d '{"key_id":"k1"}'
curl -s -X POST localhost:8000/keys/rotate -H 'X-Actor: admin' \
  -H 'Content-Type: application/json' -d '{"key_id":"k1","idempotency_key":"r-001"}'

# 加密 / 解密
curl -s -X POST localhost:8000/encrypt -H 'X-Actor: crypto-a' \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"k1","plaintext_b64":"aGVsbG8=","aad_b64":"Y3R4"}'
curl -s -X POST localhost:8000/decrypt -H 'X-Actor: crypto-a' \
  -H 'Content-Type: application/json' \
  -d '{"envelope":{...},"expected_aad_b64":"Y3R4"}'

# 审计链核验（仅 admin）
curl -s localhost:8000/audit/verify -H 'X-Actor: admin'
```

## 9. 安全说明（本地模拟边界）

- `X-Actor` 仅用于本地模拟，生产必须替换为带签名的身份令牌与真实 IAM。
- 密钥以明文形式存于本地 `keys.json`，模拟的是「受信托管平面」；
  生产应由 HSM/KMS 托管，根密钥不落普通磁盘。
- 本服务不做历史版本物理销毁（无密钥删除窗口），以保证历史密文长期可解密；
  归档保留策略可按合规要求在上层增加。
