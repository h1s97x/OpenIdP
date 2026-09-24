# =============================================================
# OpenIdP · 构建与开发命令
# -------------------------------------------------------------
# 收敛部署路径，一条命令完成「前端构建 → 内嵌 → Go 编译」。
# 常用命令：
#   make build   构建单二进制（内嵌前端 SPA）
#   make dev     并行启动后端 + 前端开发服务器
#   make embed   仅将 web/dist 复制到 Go embed 目录
#   make run     直接运行已构建的二进制
#   make docker  构建并启动 Docker Compose 栈
#   make clean   清理构建产物
# =============================================================

SHELL := /bin/bash
.PHONY: build dev embed run docker compose-up clean test

# 构建前端并产出单二进制（内嵌前端 SPA）
build:
	cd web && pnpm install && pnpm build
	rm -rf api/cmd/server/dist && mkdir -p api/cmd/server/dist
	cp -r web/dist/* api/cmd/server/dist/
	cd api && go build -o openidp ./cmd/server
	@echo "✔ 构建完成：api/openidp（单二进制，内嵌前端 SPA）"

# 仅将已构建的 web/dist 复制到 Go embed 目录（供后续 go build）
embed:
	@if [ ! -f web/dist/index.html ]; then \
		echo "✖ 未找到 web/dist/index.html，请先运行 `cd web && pnpm build`"; \
		exit 1; \
	fi
	rm -rf api/cmd/server/dist && mkdir -p api/cmd/server/dist
	cp -r web/dist/* api/cmd/server/dist/
	@echo "✔ 已复制 web/dist 到 api/cmd/server/dist"

# 开发模式：Go 单端口统一入口（:6099）
# 后端启动时设置 OPENIDP_DEV_FRONTEND_URL，使 Go 把非 API 请求反向代理到
# Vite dev server（:5173），保留 HMR 热更新；开发时只需访问 :6099 一个端口，
# 与生产内嵌模式行为一致。
# 后端编译前需存在内嵌 dist，故先复制 web/dist 到 Go embed 目录。
dev: embed
	@echo "启动开发服务器：单端口入口 http://127.0.0.1:6099 （Go 处理 API，页面代理到 Vite :5173）"
	@trap 'kill 0' INT TERM; \
	( cd api && OPENIDP_DEV_FRONTEND_URL=http://localhost:5173 go run ./cmd/server ) & \
	( cd web && pnpm dev ) & \
	wait

# 运行后端（使用已构建的二进制）
run:
	@if [ -f api/openidp ]; then \
		./api/openidp; \
	else \
		echo "✖ 未找到 api/openidp，请先运行 make build"; \
		exit 1; \
	fi

# 构建 Docker 镜像
docker-build:
	docker build -t h1s97x/openidp:latest -f Dockerfile .

# 启动 Docker Compose 栈
# 所有配置均有内置默认值，可直接启动；如需覆盖（如数据库密码）可自建 .env 文件写 OPENIDP_* 变量。
compose-up:
	docker compose up -d

docker: docker-build compose-up

# 运行 Go 单元测试
test:
	cd api && go test ./...

# 清理构建产物
clean:
	rm -rf api/openidp
	rm -rf web/dist
	rm -rf api/cmd/server/dist
	@echo "✔ 已清理构建产物（api/openidp、web/dist、api/cmd/server/dist）"
