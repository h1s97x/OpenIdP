# syntax=docker/dockerfile:1
# =============================================================
# OpenIdP · 单镜像（API + 嵌入前端 SPA）
# 多阶段构建：node 构建前端 -> golang 静态编译 -> alpine 运行时
#
# 镜像构建：
#   docker build -t h1s97x/openidp:latest -f Dockerfile .
# 也可直接用 make docker-build（镜像名集中定义在 Makefile）。
# =============================================================

# ---------- Stage 1: build frontend ----------
FROM node:22-alpine AS web
WORKDIR /app/web
RUN corepack enable && corepack prepare pnpm@10.28.2 --activate
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN CI=true pnpm install --frozen-lockfile --prefer-offline
COPY web/index.html web/tsconfig.json web/vite.config.ts ./
COPY web/public ./public
COPY web/src ./src
RUN CI=true pnpm build

# ---------- Stage 2: build Go binary ----------
FROM golang:1.25-alpine AS api
WORKDIR /app/api
ENV GOPROXY=https://goproxy.cn,direct \
    GOSUMDB=sum.golang.google.cn \
    CGO_ENABLED=0 \
    GOTOOLCHAIN=auto
# 构建元数据注入：镜像构建时可用 --build-arg 指定 VERSION/COMMIT/BUILD_DATE。
# 未指定时使用占位默认值，避免破坏现有构建流程。
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
COPY api/go.mod api/go.sum ./
RUN go mod download
COPY api/cmd ./cmd
COPY api/internal ./internal
COPY --from=web /app/web/dist ./cmd/server/dist
RUN go build \
    -ldflags="-s -w \
        -X github.com/h1s97x/openidp/api/internal/version.Version=${VERSION} \
        -X github.com/h1s97x/openidp/api/internal/version.Commit=${COMMIT} \
        -X github.com/h1s97x/openidp/api/internal/version.BuildDate=${BUILD_DATE}" \
    -o /openidp ./cmd/server

# ---------- Stage 3: runtime ----------
FROM alpine:3.20
# ca-certificates/tzdata：TLS 与时区；su-exec：入口脚本降权（支持 root 启动时自动 chown 数据卷）
RUN apk add --no-cache ca-certificates tzdata su-exec && adduser -D -u 1000 openidp
WORKDIR /app
COPY --from=api /openidp /usr/local/bin/openidp
# 入口脚本：确保数据目录存在且属主正确，并在以 root 启动时自动降权到 openidp(uid 1000)
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
# 预创建数据目录并由 openidp(uid 1000) 拥有，确保首次挂载数据卷时权限正确
RUN mkdir -p /app/data && chown -R 1000:1000 /app/data
ENV OPENIDP_ADDR=:6099 \
    OPENIDP_DATA_DIR=/app/data \
    OPENIDP_DATABASE_URL=""
EXPOSE 6099
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:6099/api/health || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
