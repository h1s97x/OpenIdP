# 08 · 构建、运行与部署

## 1. 构建方式

### 1.1 单二进制（推荐生产）

```bash
make build
# 等价于：
#   cd web && pnpm install && pnpm build
#   rm -rf api/cmd/server/dist && mkdir -p api/cmd/server/dist && cp -r web/dist/* api/cmd/server/dist/
#   cd api && go build -o openidp ./cmd/server
./api/openidp        # 或 make run
```

产物：`api/openidp`，**内嵌前端 SPA**，单文件单端口。

### 1.2 Makefile 目标一览

| 目标 | 作用 |
|------|------|
| `make build` | 前端构建 → 内嵌 → Go 编译，产出 `api/openidp` |
| `make embed` | 只把已构建的 `web/dist` 复制到 `api/cmd/server/dist`（后续自行 `go build`） |
| `make dev` | 并行启动 Go（:6099）+ Vite（:5173），Go 作为单端口统一入口反向代理到 Vite |
| `make run` | 运行已构建的二进制 |
| `make test` | `cd api && go test ./...` |
| `make docker-build` | `docker build -t h1s97x/openidp:latest -f Dockerfile .` |
| `make compose-up` | `docker compose up -d` |
| `make docker` | `docker-build` + `compose-up` |
| `make clean` | 清理 `api/openidp`、`web/dist`、`api/cmd/server/dist` |

## 2. Docker

### 2.1 三阶段构建（`Dockerfile`）

| 阶段 | 基础镜像 | 做什么 |
|------|---------|--------|
| `web` | `node:22-alpine` | corepack 启用 pnpm@10.28.2 → `pnpm install --frozen-lockfile` → `pnpm build` |
| `api` | `golang:1.25-alpine` | `CGO_ENABLED=0`；`GOPROXY=https://goproxy.cn`；拷贝 `cmd/`、`internal/`、前端 `dist` → `go build`，用 `-ldflags -X` 注入版本/Commit/构建时间 |
| runtime | `alpine:3.20` | 装 `ca-certificates`、`tzdata`、`su-exec`；建 `openidp`(uid 1000)；拷二进制与入口脚本 |

### 2.2 运行时环境

```dockerfile
ENV OPENIDP_ADDR=:6099  OPENIDP_DATA_DIR=/app/data  OPENIDP_DATABASE_URL=""
EXPOSE 6099
HEALTHCHECK CMD wget -q -O /dev/null http://127.0.0.1:6099/api/health
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
```

### 2.3 入口脚本（`scripts/entrypoint.sh`）

```sh
DATA_DIR="${OPENIDP_DATA_DIR:-${DATA_DIR:-/app/data}}"
[ -d "$DATA_DIR" ] || mkdir -p "$DATA_DIR"
if [ "$(id -u)" = "0" ]; then
    chown -R 1000:1000 "$DATA_DIR"     # 命名卷首次挂载时属主可能不对
    exec su-exec 1000:1000 /usr/local/bin/openidp "$@"
fi
exec /usr/local/bin/openidp "$@"
```

### 2.4 docker compose（`docker-compose.yml`）

三个服务：`openidp`（应用）、`openidp_postgresql`（pg 17-alpine）、`openidp_redis`（redis 7.4-alpine）。

```bash
docker compose up -d
# 访问 http://localhost:6099 → 首次进入初始化页设置管理员
```

要点：

- 数据卷 `./data:/app/data`（SQLite、`encryption.key`、`jwt/`、日志都在这里）
- PostgreSQL 默认口令 `openidp123`，**生产务必覆盖**：`OPENIDP_DATABASE_PASSWORD=强口令`
- Redis 可选：不需要就整段注释掉，应用自动降级内存缓存（`openidp_redis` 也要从 `depends_on` 移除）
- `OPENIDP_TRUST_PROXY=true`：容器直接暴露到公网时应改为 `false`，否则需配置 `OPENIDP_TRUSTED_PROXIES`

## 3. 环境变量

全部使用 `OPENIDP_` 前缀（`config.EnvPrefix`），代码位置 `api/internal/config/config.go`。

### 3.1 基础

| 变量 | 默认 | 说明 |
|------|------|------|
| `OPENIDP_ADDR` | `:6099` | 监听地址 |
| `OPENIDP_DATA_DIR` | `./data` | 数据目录（SQLite、密钥、日志、本地文件） |
| `OPENIDP_SITE_URL` | `http://localhost:6099` | **生产必须显式设置**：OAuth 回调、邮件链接、OIDC `iss`、Passkey RP |
| `OPENIDP_TIMEZONE` | `Asia/Shanghai` | IANA 时区，非法值直接启动失败 |
| `OPENIDP_LOG_LEVEL` | `info` | `debug/info/warn/error/off` |
| `OPENIDP_LOG_DIR` | `<DataDir>/log` | 置 `-` 关闭文件日志 |
| `OPENIDP_LOG_FILE_ENABLED` | `true` | |
| `OPENIDP_LOG_RETENTION_DAYS` | `7` | |
| `OPENIDP_LOG_MAX_SIZE_MB` | `64` | 单文件上限，超出切分 |

### 3.2 数据库

| 变量 | 说明 |
|------|------|
| `OPENIDP_DATABASE_URL` | 显式 DSN，**优先级最高** |
| `OPENIDP_DATABASE_TYPE` | `postgres` / `mysql` / `mariadb`；其它值 → SQLite |
| `OPENIDP_DATABASE_HOST/USER/NAME/PORT/PASSWORD/SSL_MODE` | 结构化组装 DSN |
| `OPENIDP_DB_FALLBACK` | `fail-fast`（默认）/ `sqlite` |

DSN 组装规则（`assembleDatabaseURL`）：

```
postgres → postgres://user:pass@host:port/name?sslmode=disable
mysql    → user:pass@tcp(host:port)/name?parseTime=true&charset=utf8mb4
```

### 3.3 安全与 Cookie

| 变量 | 默认 | 说明 |
|------|------|------|
| `OPENIDP_ENCRYPTION_KEY` | 自动生成 | 32 字节 hex/base64；不配置则写 `<DATA_DIR>/encryption.key` |
| `OPENIDP_JWT_KEY_DIR` | `<DATA_DIR>/jwt` | RSA 私钥目录；为空则用内存临时密钥（重启全失效） |
| `OPENIDP_SESSION_COOKIE` | `openidp_session` | |
| `OPENIDP_DEVICE_COOKIE` | `openidp_device_id` | |
| `OPENIDP_OAUTH_STATE_COOKIE` | `openidp_oauth_state` | 第三方登录 state 绑定 |
| `OPENIDP_CSRF_HEADER` | `X-OpenIdP-CSRF` | |
| `OPENIDP_SESSION_TTL_DAYS` | `14` | |
| `OPENIDP_DEVICE_TTL_DAYS` | `365` | 可信设备 TTL 兜底 |
| `OPENIDP_COOKIE_SECURE` | `auto` | `true/false/auto`（auto 按 SITE_URL 推导） |
| `OPENIDP_COOKIE_SAME_SITE` | `auto` | auto：配了 CORS 则 `none`，否则 `lax` |
| `OPENIDP_SETUP_ALLOW_REMOTE` | `true` | 是否允许非本机 IP 执行初始化 |

### 3.4 代理与真实 IP

| 变量 | 默认 | 说明 |
|------|------|------|
| `OPENIDP_TRUST_PROXY` | `true` | `none/0/false/off` 关闭转发头采信 |
| `OPENIDP_CLIENT_IP_HEADER` | `CF-Connecting-IP` | 也可用 `EO-Client-IP` / `ali-real-client-ip` |
| `OPENIDP_TRUSTED_PROXIES` | 空 | 额外可信代理网段（CIDR），如 CDN 回源段 |

取值优先级：**专用真实 IP 头 → `X-Forwarded-For`（从右往左跳过可信跳与内网）→ TCP 对端**。
即使开启 `TRUST_PROXY`，也只有 **TCP 对端落在可信网段**（默认回环 + RFC1918 + IPv6 ULA）时才采信转发头。

> ⚠️ 服务可能被任意内网主机直连时（同 VPC / K8s 同集群 / 内网跳板），应设为 `none`，
> 否则可从内网伪造 `CF-Connecting-IP` 绕过按 IP 限流。

### 3.5 缓存

| 变量 | 默认 | 说明 |
|------|------|------|
| `OPENIDP_REDIS_ADDR` | 空 | 空或连接失败 → 内存缓存 |
| `OPENIDP_REDIS_PASSWORD` | 空 | |
| `OPENIDP_REDIS_DB` | `0` | |

Redis 用于：TokenStore（CSRF/一次性凭证）、全部限流器、OAuth consent ticket、
Passkey 仪式状态、GeoIP 结果缓存。**多实例部署必须配 Redis**，否则跨实例状态不一致。

### 3.6 邮件 / 短信 / 人机验证

| 变量 | 说明 |
|------|------|
| `OPENIDP_SMTP_HOST/PORT/USER/PASSWORD/FROM/FROM_NAME` | `PORT` 默认 465；`OPENIDP_SMTP_USE_TLS` 为 STARTTLS |
| `OPENIDP_SMTP_INSECURE_SKIP_VERIFY` | 仅开发 |
| `OPENIDP_SMTP_TEMPLATE` | 自定义 HTML 模板 |
| `OPENIDP_CAPTCHA_PROVIDER` | `turnstile` / `geetest` / `none`（空则自动推导） |
| `OPENIDP_TURNSTILE_SITE_KEY/SECRET_KEY/REQUIRED_FOR_LOGIN/REQUIRED_FOR_SIGNUP/VERIFY_URL` | |
| `OPENIDP_GEETEST_CAPTCHA_ID/KEY/REQUIRED_FOR_LOGIN/REQUIRED_FOR_SIGNUP/API_DOMAIN/BIND_MODE` | |

> 这些都只是**初始默认值**：管理后台保存后以数据库为准，改后台立即生效无需重启。

### 3.7 存储 / CDN / CORS / Webhook

| 变量 | 默认 | 说明 |
|------|------|------|
| `OPENIDP_STORAGE_BACKEND` | `local` | `local` / `s3` |
| `OPENIDP_STORAGE_LOCAL_DIR` | `<DATA_DIR>` | |
| `OPENIDP_STORAGE_S3_ENDPOINT/BUCKET/REGION/PREFIX/KEY_ID/SECRET/PUBLIC_BASE_URL` | | |
| `OPENIDP_CDN_BASE_URL` | `` | 前端字体 CDN；`-` 或空关闭 |
| `OPENIDP_CORS_ALLOWED_ORIGINS` | 空 | 前后端分离必须设置 |
| `OPENIDP_DEV_FRONTEND_URL` | 空 | 仅开发；指向 Vite :5173 |
| `OPENIDP_WEBHOOK_URLS` | 空 | 逗号分隔 |
| `OPENIDP_WEBHOOK_SECRET` | 空 | HMAC-SHA256 签名（`X-OpenIdP-Signature`） |

### 3.8 第三方登录凭据（作为 seed 初始值）

`OPENIDP_GITHUB_CLIENT_ID/SECRET`、`OPENIDP_GOOGLE_*`、`OPENIDP_MICROSOFT_*`、
`OPENIDP_QQ_*`、`OPENIDP_GITEE_*`、`OPENIDP_LINUXDO_*`。

### 3.9 品牌

`OPENIDP_SITE_NAME`（`openidp`）、`OPENIDP_SITE_DISPLAY`（`OpenIdP`）、
`OPENIDP_SITE_LOGO`、`OPENIDP_SITE_FAVICON`。

### 3.10 日志开关

`OPENIDP_ACCESS_LOG_ENABLED`、`OPENIDP_AUDIT_LOG_ENABLED`、`OPENIDP_CONFIG_LOG_ENABLED`、
`OPENIDP_ACCESS_LOG_SKIP_HEALTH`（默认 true，健康检查高频无记录价值）。

## 4. 反向代理

完整示例见 `nginx-separated.example.conf`。关键点摘录：

### 4.1 OIDC 路径必须前缀匹配

```nginx
location ^~ /.well-known/ { ... }    # ✅
location ^~ /login/oauth/ { ... }    # ✅
location ~ ^/\.well-known/ { ... }   # ❌ 面板自带的隐藏文件规则可能拦截
```

### 4.2 不要手写 X-Real-IP / CF-Connecting-IP

```nginx
# ⚠️ CDN 场景下这两行是错的：$remote_addr 是 CDN 回源节点 IP，不是用户 IP
proxy_set_header X-Real-IP        $remote_addr;
proxy_set_header CF-Connecting-IP $remote_addr;
```

CDN 专用头由 Nginx 默认透传，无需设置。客户端 IP 的采信由后端可信网段机制控制。

### 4.3 缓存策略（与内嵌模式一致）

| 路径 | Cache-Control |
|------|---------------|
| `/assets/*`（Vite 指纹） | `public, max-age=31536000, immutable` |
| `/images/*` | `public, max-age=86400` |
| `/` → index.html | `no-cache`（始终回源校验） |
| `/api`、`/.well-known`、`/login/oauth` | `no-store` |

### 4.4 前后端分离

后端需要：

```
OPENIDP_CORS_ALLOWED_ORIGINS=https://auth.example.com
OPENIDP_SITE_URL=https://auth.example.com
OPENIDP_WEBAUTHN_ORIGIN=https://auth.example.com
```

⚠️ **跨"站"部署（不同 eTLD+1）必须 HTTPS**：
跨源请求要带会话 Cookie → `SameSite` 被设为 `None` → 浏览器强制要求 `None` 必须带 `Secure`
→ 非 HTTPS 下 Cookie 被直接丢弃，表现为"接口能调通但始终未登录"。
仅同站子域（`auth.example.com` ↔ `api.example.com`）用默认 `Lax` 即可。

前端必须用 `credentials: 'include'`（本项目已内置）。

## 5. 首次部署流程

1. `docker compose up -d`（或运行二进制）
2. 访问 `http://<host>:6099` → 自动跳转 `/setup`
3. 设置管理员账号与密码（`POST /api/v1/setup`）
4. 登录 → 进入管理后台 `/admin/settings`
5. 建议依次配置：
   - **品牌信息**：站点名、Logo、默认语言、页脚备案号
   - **站点 URL**（`brand` 分区）：OIDC 回调与邮件链接的基础
   - **登录安全**：密码策略、注册开关、邮箱域名白名单、通行密钥、人机验证
   - **消息服务**：SMTP（否则验证码只打日志）、短信（如需手机号验证）
   - **登录提供商**：启用第三方登录并填凭据
   - **应用管理**：创建 OAuth 客户端，登记回调地址
   - **数据与运维**：审计保留、存储后端、备份策略

## 6. 排障速查

| 现象 | 排查方向 |
|------|---------|
| 启动即退出，日志有时区错误 | `OPENIDP_TIMEZONE` 值非法（必须是 IANA 名，如 `Asia/Shanghai`） |
| 启动报错 `postgres 连接失败` | 默认 fail-fast；如需降级设 `OPENIDP_DB_FALLBACK=sqlite` |
| "接口能调通但始终未登录" | 跨站部署 Cookie `SameSite=None` 但非 HTTPS；或 `OPENIDP_SITE_URL` 与实际域名不符 |
| 所有写操作 403 | CSRF 失败：服务重启后 TokenStore 清空，前端会自动刷新重试一次；若持续失败检查 `OPENIDP_CSRF_HEADER` |
| 登录后立刻掉线 | 会话 Cookie 的 `Secure` 与实际协议不匹配（`auto` 按 SITE_URL 推导，注意 SITE_URL 是否 https） |
| RP 报 `iss mismatch` | 未配置 `OPENIDP_SITE_URL`，`iss` 由请求 Host 推导出错 |
| 通行密钥不可用 | 管理后台未开启；或未配置站点 URL；或 origin 非 HTTPS（localhost 除外） |
| 限流误伤真实用户 | `OPENIDP_TRUST_PROXY` 或 `OPENIDP_TRUSTED_PROXIES` 未正确配置，取到的 IP 是代理 IP |
| 邮件验证码收不到 | SMTP 未配置时验证码只打**终端**（`logging.Sensitive`）；检查 `OPENIDP_SMTP_*` 或后台「消息服务」 |
| 头像 403 | 文件读取端点被加进 CSRF 组（`<img>` 不带自定义头） |
| 恢复备份后凭据全部失效 | 未同时备份 `DATA_DIR/encryption.key` 与 `DATA_DIR/jwt/rsa.pem` |
| 日志文件没生成 | `OPENIDP_LOG_FILE_ENABLED=false` 或 `OPENIDP_LOG_DIR=-`；或目录不可写（会降级仅 stderr） |

## 7. 测试

```bash
make test                      # cd api && go test ./...
cd api && go test ./internal/handler/ -run TestOAuth -v
cd web && pnpm lint
```

测试文件与实现文件同目录，命名 `*_test.go` / `*_test.ts`。
`internal/handler/` 下的测试较完整（含 `zz_oauth_flow_test.go`、`zz_smoke_test.go`、
`security_test.go`、`performance_fixes_test.go`、`regression_fixes_test.go`），
**修改 handler 后务必跑一遍**。
