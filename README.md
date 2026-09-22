# 本地信封加密与密钥轮换（Envelope Key Management）

用本地存储模拟 KMS 的密钥托管与归档，演示：

- 主密钥**创建 / 轮换 / 版本归档**：任一时刻仅一个版本用于新加密，历史版本永久可解密；
- **信封加密 + 三层完整性校验**：元数据 / AAD / 密文被改动分别得到可区分错误，绝不返回错误明文；
- **按调用方授权**：区分「无操作权限」与「超出密钥范围」，拒绝原因可区分；
- **哈希链审计**：每次密钥状态变更留痕，重复/并发调用后状态与审计仍自洽可核验；
- 覆盖**轮换期间并发加解密、历史密文解密、篡改、越权**的测试，日志打印所用密钥版本与判定依据。

## 快速开始

```bash
uv sync
uv run pytest                      # 全量测试
uv run pytest -o log_cli=true -o log_cli_level=INFO   # 查看密钥版本/判定依据日志
uv run uvicorn main:app --reload   # 启动 HTTP 服务
```

## HTTP 接口

| 方法/路径 | 调用方 | 说明 |
|---|---|---|
| `POST /keys` | admin | 创建主密钥（初始 v1） |
| `POST /keys/rotate` | admin | 轮换（可带 `idempotency_key`） |
| `GET  /keys/{key_id}` | 授权方 | 查询当前版本与归档版本 |
| `POST /encrypt` | 加密方 | 信封加密，响应回显 `key_version` |
| `POST /decrypt` | 加密方 | 按信封内版本定位归档密钥解密 |
| `GET  /audit/verify` | admin | 重算审计哈希链 |
| `GET  /health` | 任意 | 健康检查 |

身份通过 `X-Actor` 头传入（本地模拟）。预置身份：`admin`、`crypto-a`(scope k1/k2)、
`crypto-b`(scope k3)、`auditor`(只读)。

## 进一步阅读

- 密钥版本模型、轮换并发正确性、信封结构、错误分类与审计链：见 [docs/DESIGN.md](docs/DESIGN.md)。
