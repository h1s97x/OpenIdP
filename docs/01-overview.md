# 01 · 项目总览与定位

## 1. 这是什么

OpenIdP（OpenIdP）是一个**自托管统一身份认证平台**。它的职责是：

1. 维护唯一的用户目录（账号、凭据、资料、身份绑定）；
2. 提供浏览器登录门户（多种登录方式 + 二次验证 + 设备管理）；
3. 作为 **OIDC / OAuth2 授权服务器**，向任意第三方应用签发身份令牌；
4. 提供管理后台，配置站点品牌、登录提供商、安全策略、消息服务、存储与审计。

## 2. 是 IdP 还是 IAM？

**结论：核心是 IdP（身份提供方），并往 IAM 方向做了延伸，但不等价于完整 IAM。**

### 2.1 判定依据（来自代码，不是宣传语）

| 证据 | 位置 | 说明 |
|------|------|------|
| 实现 OIDC Discovery 文档 | `api/internal/handler/oidc.go` `HandleDiscovery` | 声明 `issuer`、`authorization_endpoint`、`token_endpoint`、`jwks_uri`、`userinfo_endpoint` |
| RSA 私钥 + JWKS 发布 | `api/internal/oidc/oidc.go` `Provider.JWKS/SignIDToken` | RS256 签发 `id_token`，公开公钥供 RP 验签 |
| 授权码 + PKCE(S256) | `HandleAuthorize` / `tokenByCode` | 标准授权码流程，public client 强制 PKCE |
| 令牌体系 | `oidc_token.go` | access / refresh / id_token，refresh 轮换 + 重用检测 |
| 用户主体 `subject` | `models.User.Subject` | 每个用户有唯一 `sub`，正是 OIDC 的核心概念 |
| **没有** SAML | 全仓库检索无 SAML/断言签名实现 | 不做到 SAML 2.0 SP/IdP |
| **没有** 角色/权限策略引擎 | 仅有 `User.IsAdmin` 布尔位 | 无 RBAC/ABAC、无策略语言、无属性授权（PDP） |
| **没有** 目录同步 | 无 SCIM / LDAP | 不接管企业目录 |
| 有授权记录（grant） | `models.Grant`、`/me/grants` | 有基础的"应用授权管理"，属于 IAM 的授权可见性 |

### 2.2 一句话结论

> **OpenIdP 是 IdP（OIDC Provider / OP），并带有一部分轻量 IAM 能力（用户目录、登录策略、审计、应用授权管理），但不包含企业 IAM 通常具备的 RBAC/ABAC 权限引擎、SSO 联邦（SAML/LDAP/SCIM）与集中式策略决策。**

对绝大多数使用场景（"帮我给一堆内部/第三方应用做统一登录"），它扮演的就是 IdP；
如果你的需求是"集中管理上千条角色权限策略并下发到各系统"，OpenIdP 只覆盖了身份认证这一段。

### 2.3 与同类概念对照

| 概念 | 职责 | OpenIdP 是否覆盖 |
|------|------|----------------|
| IdP | 认证 + 令牌签发 + 用户目录 | ✅ 完整覆盖 |
| OIDC OP | Discovery/JWKS/授权码/UserInfo | ✅ 完整覆盖 |
| OAuth2 AS | 授权/令牌/内省/撤销/设备码 | ✅ 完整覆盖 |
| IGA / IAM | 角色、权限、审批、目录同步、生命周期治理 | ⚠️ 仅"审批式账号注销" + 基础用户管理，其余缺失 |

## 3. 技术栈

### 后端

| 项 | 选型 | 说明 |
|----|------|------|
| 语言 | Go 1.25 | `api/go.mod` |
| HTTP 路由 | `github.com/go-chi/chi/v5` | 轻量、无框架魔法 |
| ORM | `github.com/uptrace/bun` | pg / mysql / sqlite 三种 dialect |
| JWT/JWK | `github.com/go-jose/go-jose/v4` | RS256 签发 + JWKS |
| WebAuthn | `github.com/go-webauthn/webauthn` | 通行密钥 |
| 缓存 | `github.com/redis/go-redis/v9` + 自研内存实现 | 带熔断降级 |
| IP 归属地 | `ip2region` + `maxminddb` | 内置库，可配自定义库 |
| SMTP | 标准库 `net/smtp` | 自研模板渲染 |
| 无 CGO | 纯 Go SQLite（`modernc.org/sqlite`） | 单二进制可静态编译 |

### 前端

| 项 | 选型 |
|----|------|
| 框架 | React 18 + TypeScript 5 |
| 构建 | Vite 6（`pnpm@10.28.2`） |
| 路由 | react-router-dom 7（BrowserRouter） |
| 数据层 | @tanstack/react-query 5 |
| 样式 | Tailwind CSS v4（`@tailwindcss/vite`） |
| 图表 | recharts（单独分包，懒加载） |
| i18n | i18next + react-i18next（zh-CN / zh-TW / ja / en，字典按需加载） |
| 图标 | lucide-react |

## 4. 仓库结构

```
.
├── api/                       # Go 后端
│   ├── cmd/
│   │   ├── server/main.go     # 主进程：初始化 + 路由挂载 + 内嵌 SPA
│   │   ├── initdb/main.go     # 建库/迁移辅助命令
│   │   └── seeddemo/main.go   # 演示数据种子
│   ├── internal/              # 全部业务包（见 03-backend-modules.md）
│   └── go.mod
├── web/                       # React 前端
│   ├── src/
│   │   ├── pages/             # 页面（含 pages/admin/）
│   │   ├── components/        # ui / layout / appearance / settings
│   │   ├── hooks/             # useSession / useSetup / useTheme ...
│   │   ├── lib/               # api client、类型、captcha、webauthn
│   │   └── i18n/              # 四语言字典
│   ├── public/images/         # logo.svg / avatar.svg 等
│   └── vite.config.ts
├── docs/                      # 本文档
├── scripts/entrypoint.sh      # 容器入口（降权到 uid 1000）
├── Dockerfile                 # 三阶段：node build → go build → alpine
├── docker-compose.yml         # openidp + postgres + redis
├── nginx-separated.example.conf  # 前后端分离部署示例
├── Makefile                   # build / dev / embed / run / test / clean
└── README.md / README_EN.md
```

## 5. 核心设计原则（贯穿全仓库）

读代码时会反复遇到下面几条约定，先建立认知能省很多时间：

1. **开箱即用 + 自动降级**
   数据库未配置→SQLite；Redis 未配置→内存缓存；SMTP 未配置→验证码只打日志；存储未配置→本地磁盘。
   但**生产环境的关键降级必须显式开关**（如 `OPENIDP_DB_FALLBACK=sqlite`），默认 fail-fast，避免"用户数据消失"。

2. **一切敏感值加密落库**
   `internal/appcrypto`（AES-256-GCM）加密 OAuth ClientSecret、SMTP 密码、验证码密钥、TOTP 密钥；
   会话 ID 在库中只存 SHA-256 摘要；客户端密钥与密码只存 bcrypt 哈希。

3. **不可信输入一律不放行**
   `redirect_uri` 不在白名单 → 返回 JSON 错误而不重定向（防开放重定向）；
   scope 必须收敛到客户端登记范围；外链一律 `safeInternalPath` 过滤。

4. **热更新靠原子指针**
   管理后台可改配置（人机验证 / 短信 / 存储），读路径用 `atomic.Pointer` 取不可变快照，写路径整体替换。

5. **注释解释"为什么"**
   本项目注释密度很高，且几乎都在解释"为什么这么写、不这么写会出什么问题"。
   修改代码前**先读注释**，多数"看起来多余"的校验都是在补历史漏洞。

6. **配置以数据库为准，env 只是默认值**
   站点设置、安全策略、邮件、短信、人机验证等都有单行配置表，管理后台改动即时生效；
   环境变量只在首次 seed 时作为初始值。

## 6. 快速定位：我要改 XX 应该看哪里

| 需求 | 入口文件 |
|------|---------|
| 新增一个 HTTP 端点 | `api/internal/handler/router.go` + 对应 `handler/*.go` |
| 改登录流程 | `api/internal/handler/session.go` |
| 改 OIDC 令牌签发 | `api/internal/handler/oidc_token.go`、`internal/oidc/oidc.go` |
| 新增数据库表/字段 | `api/internal/models/models.go` + `internal/db/db.go` 的 `Migrate` |
| 新增第三方登录提供商 | `api/internal/oauth2/oauth2.go` 的 `init()` 注册表 |
| 新增短信服务商 | `api/internal/sms/*.go` + `sms.NewProvider` |
| 新增管理后台配置项 | `api/internal/handler/admin_*.go` + `web/src/pages/admin/AdminSettingsPage.tsx` |
| 新增前端页面 | `web/src/pages/*.tsx` + `web/src/App.tsx` 路由 |
| 改某个环境变量 | `api/internal/config/config.go` |
