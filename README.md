<div align="center">

<img src="web/public/images/logo.svg" alt="OpenIdP" width="88" />

# OpenIdP

**开箱即用的自托管统一身份认证平台（IdP）**

简体中文 · [English](./README_EN.md) · 📖 [项目文档](./docs/)

</div>

---

## 这是什么

OpenIdP 对外提供三件事：

1. 维护唯一的用户目录（账号、凭据、资料、身份绑定）；
2. 提供浏览器登录门户（多种登录方式 + 二次验证 + 设备管理）；
3. 作为 **OIDC / OAuth2 授权服务器**，向任意第三方应用签发身份令牌。

管理后台负责站点品牌、登录提供商、安全策略、消息服务、存储与审计的全配置化。

> 定位说明：核心是 **IdP（OIDC Provider）**，并延伸了部分轻量 IAM 能力（用户目录、
> 登录策略、审计、应用授权管理）。**不包含** SAML / LDAP / SCIM 联邦，
> 也没有 RBAC/ABAC 策略引擎——判定依据见 [`docs/01-overview.md`](./docs/01-overview.md)。

## ✨ 特性

- **多种登录方式**：密码、邮箱验证码、通行密钥（WebAuthn）、6 家第三方社交登录
- **双重安全**：双因素认证（TOTP）、设备可信管理、人机验证（极验 / Cloudflare Turnstile）
- **标准协议**：完整实现 OIDC / OAuth2 授权码流程（含 PKCE 与 refresh_token），可对接任意第三方应用
- **完整管理后台**：用户管理、审计日志、登录提供商、邮件服务、人机验证、站点品牌等全配置化
- **单容器部署**：Go 后端内嵌前端 SPA，单端口一条命令拉起整套服务
- **多数据库**：SQLite（开发）/ PostgreSQL 17 / MySQL / MariaDB（生产），零代码切换
- **多语言**：简体中文 / 繁體中文 / 日本語 / English
- **统一时区**：系统默认 Asia/Shanghai（UTC+8），后端日志、界面时间与按天统计口径一致，可用 `OPENIDP_TIMEZONE` 指定其他 IANA 时区
- **零外部依赖**：默认不加载任何第三方 CDN 资源，可直接用于内网 / 离线环境

## 🚀 快速开始

```bash
docker compose up -d
```

启动后访问 <http://localhost:6099>，首次访问进入初始化页设置管理员账号。所有配置均有内置默认值，开箱即用。

本地开发：

```bash
make dev    # 一条命令并行启动 Go 后端(:6099) + Vite(:5173)
```

开发模式由 Go 作为单端口统一入口（:6099），非 API 请求反向代理到 Vite dev server，
保留 HMR 热更新，与生产内嵌模式行为一致。

## ⚙️ 配置约定

所有环境变量统一使用 **`OPENIDP_`** 前缀，前缀只在
[`api/internal/config/config.go`](./api/internal/config/config.go) 的 `EnvPrefix` 一处定义。
完整的变量清单见 [`docs/08-deployment.md`](./docs/08-deployment.md)。

几个值得注意的默认值：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `OPENIDP_ADDR` | `:6099` | 监听地址 |
| `OPENIDP_DATA_DIR` | `./data` | 数据目录（SQLite / JWT 密钥 / 日志） |
| `OPENIDP_CDN_BASE_URL` | 空 | **默认不依赖任何外部 CDN**；需要自建字体 CDN 时显式配置 |
| `OPENIDP_DB_FALLBACK` | `fail-fast` | 生产环境数据库故障时立即失败，避免静默降级导致数据"消失" |
| `OPENIDP_TRUST_PROXY` | `true` | 解析转发头取真实客户端 IP；直接暴露公网时应设为 `false` |

配置以数据库为准，环境变量只作首次初始化时的默认值——管理后台改动即时生效。

## 📖 文档

项目内自带完整文档，见 [`docs/`](./docs/)：

| 文档 | 说明 |
|------|------|
| [项目总览与定位](./docs/01-overview.md) | 是什么、是 IdP 还是 IAM、技术选型 |
| [架构设计](./docs/02-architecture.md) | 进程结构、请求链路、模块划分 |
| [后端模块](./docs/03-backend-modules.md) | 各 `internal/*` 包的职责 |
| [认证与 OIDC](./docs/04-auth-and-oidc.md) | 登录流程、令牌签发、PKCE |
| [数据模型](./docs/05-data-model.md) | 表结构 |
| [API 参考](./docs/06-api-reference.md) | 端点清单 |
| [前端](./docs/07-frontend.md) | 页面、状态与构建 |
| [部署](./docs/08-deployment.md) | Docker / 单二进制 / 前后端分离、全部环境变量 |
| [安全](./docs/09-security.md) | 密钥管理、限流、Cookie 策略 |
| [术语表](./docs/10-glossary.md) | 名词解释 |

## 🛠️ 技术栈

**后端**：Go 1.25 · chi · bun ORM · go-jose（RS256 + JWKS）· WebAuthn · 纯 Go SQLite（无 CGO）

**前端**：React 18 · Vite 6 · TypeScript 5 · Tailwind CSS v4 · TanStack Query 5 · i18next

## 📦 仓库结构

```
.
├── api/                       # Go 后端
│   ├── cmd/
│   │   ├── server/            # 主进程：初始化 + 路由挂载 + 内嵌 SPA
│   │   ├── migrate/           # 建库 / 迁移辅助命令
│   │   └── seed/              # 演示数据种子
│   └── internal/              # 全部业务包（见 docs/03-backend-modules.md）
├── web/                       # React 前端
├── docs/                      # 项目文档
├── scripts/entrypoint.sh      # 容器入口（降权到 uid 1000）
├── Dockerfile                 # 三阶段：node build → go build → alpine
└── docker-compose.yml         # openidp + postgres + redis
```

## 📄 许可证与署名

本项目基于 [MIT License](./LICENSE) 开源。

OpenIdP 是在 **Nimbus（云坠通行证）** 基础上进行品牌重构与结构调整的衍生作品。
依照 MIT 协议要求，原始版权声明与许可证全文已在 [`LICENSE`](./LICENSE) 中**原样保留**，
来源与衍生说明见 [`NOTICE`](./NOTICE)。
