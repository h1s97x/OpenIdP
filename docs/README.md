# OpenIdP Code Wiki

> 面向开发者的代码级文档。基于仓库 `main` 分支（提交 `80cfd02`，init from source）通读源码整理。
> 目标读者：接手本项目二次开发、排查线上问题、评审安全实现的人。

OpenIdP（OpenIdP）是一个**开箱即用的自托管统一身份认证平台（IdP）**：
Go 后端内嵌 React SPA，单容器单端口即可跑起完整的 OIDC/OAuth2 认证中心 + 用户自助门户 + 管理后台。

---

## 目录

| 文档 | 内容 |
|------|------|
| [01-overview.md](./01-overview.md) | 项目定位（IdP vs IAM）、技术栈、仓库结构、核心设计原则 |
| [02-architecture.md](./02-architecture.md) | 整体架构、请求生命周期、分层与依赖关系 |
| [03-backend-modules.md](./03-backend-modules.md) | 后端各 `internal/*` 包职责与关键类/函数 |
| [04-auth-and-oidc.md](./04-auth-and-oidc.md) | 认证链路与 OIDC/OAuth2 协议实现细节 |
| [05-data-model.md](./05-data-model.md) | 数据模型、表结构与迁移机制 |
| [06-api-reference.md](./06-api-reference.md) | HTTP 端点清单与分组说明 |
| [07-frontend.md](./07-frontend.md) | 前端目录结构、路由、状态管理与构建策略 |
| [08-deployment.md](./08-deployment.md) | 构建、运行、Docker、环境变量、反向代理、排障 |
| [09-security.md](./09-security.md) | 安全设计要点（会话、CSRF、限流、加密、防爆破） |
| [10-glossary.md](./10-glossary.md) | 术语表与常见问答 |

---

## 30 秒速览

- **形态**：单二进制（Go 1.25 + 内嵌前端）→ 单容器 / 单端口 `:6099`
- **协议**：OIDC Discovery、授权码 + PKCE(S256)、refresh_token（含轮换与重用检测）、UserInfo、Introspect、Revoke、Device Code（RFC 8628）
- **登录方式**：密码、邮箱验证码、通行密钥（WebAuthn）、6 家内置第三方（GitHub/Google/Microsoft/QQ/Gitee/LINUX DO）+ 自定义 OAuth2
- **二次安全**：TOTP、恢复码、可信设备跳过、人机验证（Turnstile / 极验）
- **数据**：SQLite（默认）/ PostgreSQL / MySQL / MariaDB，bun ORM，运行期零代码切换
- **缓存**：Redis 可选，带熔断降级到进程内内存缓存
- **后端入口**：`api/cmd/server/main.go`
- **前端入口**：`web/src/main.tsx` → `web/src/App.tsx`

## 相关链接

- 在线文档：<https://openidp.example.com>
- 仓库：<https://cnb.cool/h1s97x/whccb/OpenIDP>

---

## 如何阅读这套文档

- **刚接手项目** → 先读 `01-overview.md`（定位与结构）+ `02-architecture.md`（架构与启动流程）
- **要改代码** → `03-backend-modules.md`（模块与函数索引）+ `07-frontend.md`
- **排查登录/授权问题** → `04-auth-and-oidc.md` + `10-glossary.md` 的 FAQ
- **部署上线** → `08-deployment.md` + `09-security.md` 的上线检查清单
- **只想快速接入** → `10-glossary.md` 的 Q2

文档中标注的文件路径均相对于仓库根目录，可直接按路径跳转源码。
