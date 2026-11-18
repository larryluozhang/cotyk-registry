# COTYK Bridge Registry（联邦 P2：纯目录服务）

中央注册表只回答一个问题：「这个 Realm 里有哪些桥、在哪、是否在线」。它不是认证中心，也不是信任根。

## 信任模型

- 桥主动注册 + 心跳；注册表**绝不**主动请求任何注册的 URL（防 SSRF，代码内无 HTTP 客户端）。
- 注册/心跳均要求 Ed25519 签名（公钥随注册上报、与签名同验——签名者持有该私钥）。
- 客户端（app）首次配对时钉扎桥公钥；注册表被黑改 endpoint 也骗不了 app（app 侧比对钉扎公钥）。
- 元数据最小化：`realm_id / bridge_id / host_name / endpoint / public_key / capabilities / status / last_seen / registration_seq`。不存 backends、token、路径。

## API

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/api/v1/bridges/register` | 桥 Ed25519 签名 | 注册/更新；`registration_seq` 每桥单调递增 |
| POST | `/api/v1/bridges/heartbeat` | 桥 Ed25519 签名（含 ts 防重放 ±60s） | 更新 `last_seen`；超 90s 无心跳即 offline |
| GET | `/api/v1/realms/{realm_id}/bridges` | 可选成员凭据（`REGISTRY_MEMBER_TOKEN` 配置后强制） | 在线桥目录（含公钥，供 app 钉扎比对） |
| DELETE | `/api/v1/bridges/{bridge_id}` | Owner 凭据（Bearer `REGISTRY_OWNER_TOKEN`） | 删除桥记录 |
| GET | `/api/v1/health` | 无 | 存活探针 |

### 签名格式（canonical string，UTF-8）

- 注册：`cotyk-reg-v1|{realm_id}|{bridge_id}|{host_name}|{endpoint}|{public_key_hex}|{capabilities_json}`
  - `capabilities_json`：按键排序、无空格的紧凑 JSON（服务端会对收到的 capabilities 重序列化后验签，桥端需同样序列化）。
- 心跳：`cotyk-hb-v1|{bridge_id}|{status}|{ts}`（`ts` 为 Unix 秒）。
- 签名为 Ed25519（64 字节）hex，公钥为 32 字节 hex。

### 限流

每客户端 IP 滑动窗口（60s）：注册 30 次/分，其余 120 次/分，超限 429。

## 本地运行

```bash
python3 -m pip install -r requirements.txt
python3 -m registry --host 0.0.0.0 --port 9400 --db registry.db
```

环境变量：`REGISTRY_DB_PATH` / `REGISTRY_HOST` / `REGISTRY_PORT` / `REGISTRY_OWNER_TOKEN` / `REGISTRY_MEMBER_TOKEN`。

## G0 自测

```bash
python3 scripts/selftest.py
```

全部在进程内 ASGI 跑（不开网络口），覆盖：注册验签、seq 单调、坏签名拒绝、endpoint 校验、目录钉扎字段、成员凭据强制、心跳验签/防重放、90s 离线判定、Owner 删除、限流、无出站 HTTP 断言。

## deck 部署（主控执行）

见 `deploy/cotyk-registry.service`（systemd --user，端口 9400）。启用前必须设置真实 `REGISTRY_OWNER_TOKEN`。
