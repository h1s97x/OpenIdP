<div align="center">

<img src="web/public/images/logo.svg" alt="OpenIdP" width="88" />

# OpenIdP

**A self-hosted unified identity provider (IdP) that works out of the box**

English · [简体中文](./README.md) · 📖 [Documentation](./docs/)

</div>

---

## What it is

OpenIdP does three things:

1. Maintains a single user directory (accounts, credentials, profiles, identity bindings).
2. Serves a browser sign-in portal (multiple auth methods, second factor, device management).
3. Acts as an **OIDC / OAuth2 authorization server**, issuing identity tokens to any third-party application.

The admin console makes site branding, login providers, security policy, mail service,
storage and auditing fully configurable.

> Scope: the core is an **IdP (OIDC Provider)** with a light IAM layer (user directory,
> sign-in policy, auditing, application grant management). It does **not** include
> SAML / LDAP / SCIM federation or an RBAC/ABAC policy engine — see
> [`docs/01-overview.md`](./docs/01-overview.md) for the evidence behind this.

## ✨ Features

- **Multiple sign-in methods**: password, email code, passkeys (WebAuthn), 6 third-party social providers
- **Layered security**: two-factor authentication (TOTP), trusted device management, human verification (GeeTest / Cloudflare Turnstile)
- **Standard protocols**: full OIDC / OAuth2 authorization code flow (PKCE & refresh_token), works with any third-party application
- **Complete admin console**: user management, audit log, login providers, mail service, captcha, site branding — all configurable
- **Single-container deployment**: the Go backend embeds the frontend SPA — one port, one command
- **Multi-database**: SQLite (development) / PostgreSQL 17 / MySQL / MariaDB (production), zero-code switching
- **Multi-language**: 简体中文 / 繁體中文 / 日本語 / English
- **Unified timezone**: defaults to Asia/Shanghai (UTC+8); backend logs, UI timestamps and daily statistics share one timezone, configurable via `OPENIDP_TIMEZONE`
- **No external dependencies**: no third-party CDN assets are loaded by default, so it works on isolated or offline networks

## 🚀 Quick Start

```bash
docker compose up -d
```

Visit <http://localhost:6099> after startup. The first visit lands on the setup page to
create the admin account. Sensible defaults are built in — ready to use out of the box.

Local development:

```bash
make dev    # starts the Go backend (:6099) + Vite (:5173) in parallel
```

In dev mode Go is the single entry point (:6099) and reverse-proxies non-API requests to
the Vite dev server, keeping HMR while behaving like the production embedded build.

## ⚙️ Configuration

Every environment variable uses the **`OPENIDP_`** prefix, which is defined in exactly one
place: `EnvPrefix` in [`api/internal/config/config.go`](./api/internal/config/config.go).
The full variable list lives in [`docs/08-deployment.md`](./docs/08-deployment.md).

Defaults worth knowing:

| Variable | Default | Notes |
|----------|---------|-------|
| `OPENIDP_ADDR` | `:6099` | Listen address |
| `OPENIDP_DATA_DIR` | `./data` | Data directory (SQLite / JWT keys / logs) |
| `OPENIDP_CDN_BASE_URL` | empty | **No external CDN by default**; set it to use your own font CDN |
| `OPENIDP_DB_FALLBACK` | `fail-fast` | Fail immediately on database failure instead of silently degrading to an empty SQLite file |
| `OPENIDP_TRUST_PROXY` | `true` | Parse forwarding headers for the real client IP; set to `false` if the port is exposed directly |

Configuration is database-backed: environment variables only seed the initial values on
first boot, and admin console changes take effect immediately.

## 📖 Documentation

Full documentation ships in [`docs/`](./docs/):

| Document | Description |
|----------|-------------|
| [Overview & positioning](./docs/01-overview.md) | What it is, IdP vs IAM, tech choices |
| [Architecture](./docs/02-architecture.md) | Process layout, request path, module map |
| [Backend modules](./docs/03-backend-modules.md) | Responsibilities of each `internal/*` package |
| [Auth & OIDC](./docs/04-auth-and-oidc.md) | Sign-in flows, token issuance, PKCE |
| [Data model](./docs/05-data-model.md) | Tables and relations |
| [API reference](./docs/06-api-reference.md) | Endpoint list |
| [Frontend](./docs/07-frontend.md) | Pages, state and build |
| [Deployment](./docs/08-deployment.md) | Docker / single binary / separated frontend, all env vars |
| [Security](./docs/09-security.md) | Key management, rate limiting, cookie policy |
| [Glossary](./docs/10-glossary.md) | Terminology |

## 🛠️ Tech Stack

**Backend**: Go 1.25 · chi · bun ORM · go-jose (RS256 + JWKS) · WebAuthn · pure-Go SQLite (no CGO)

**Frontend**: React 18 · Vite 6 · TypeScript 5 · Tailwind CSS v4 · TanStack Query 5 · i18next

## 📦 Repository Layout

```
.
├── api/                       # Go backend
│   ├── cmd/
│   │   ├── server/            # Main process: bootstrap + routes + embedded SPA
│   │   ├── migrate/           # Schema migration helper
│   │   └── seed/              # Demo data seeder
│   └── internal/              # All business packages (see docs/03-backend-modules.md)
├── web/                       # React frontend
├── docs/                      # Project documentation
├── scripts/entrypoint.sh      # Container entrypoint (drops to uid 1000)
├── Dockerfile                 # Three stages: node build → go build → alpine
└── docker-compose.yml         # openidp + postgres + redis
```

## 📄 License & Attribution

Released under the [MIT License](./LICENSE).

OpenIdP is a derivative work based on **Nimbus (云坠通行证)**, rebuilt with its own
branding, module layout and configuration layer. As required by the MIT License, the
original copyright notice and the full license text are **retained verbatim** in
[`LICENSE`](./LICENSE); see [`NOTICE`](./NOTICE) for provenance details.
