#!/bin/sh
# =============================================================
# OpenIdP 入口脚本
# -------------------------------------------------------------
# 以非 root 用户（uid 1000）运行，负责：
#   1. 确保数据目录存在且属主正确（首次挂载命名卷时目录可能为空/权限不符）
#   2. 首次运行时初始化默认配置
#   3. 转发原进程信号，优雅退出
# =============================================================
set -e

# 数据目录（默认 /app/data，可被 OPENIDP_DATA_DIR 覆盖）
DATA_DIR="${OPENIDP_DATA_DIR:-${DATA_DIR:-/app/data}}"

# 确保数据目录存在且归当前用户（非 root 运行时需有写权限）
if [ ! -d "$DATA_DIR" ]; then
    mkdir -p "$DATA_DIR"
fi

# 当以 root 启动时，将数据目录属主调整为运行用户（uid 1000），便于挂载卷初始化
if [ "$(id -u)" = "0" ]; then
    chown -R 1000:1000 "$DATA_DIR" 2>/dev/null || true
    exec su-exec 1000:1000 /usr/local/bin/openidp "$@"
fi

# 非 root 用户直接启动
exec /usr/local/bin/openidp "$@"
