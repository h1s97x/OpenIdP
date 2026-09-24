package main

import (
	"context"
	"log"
	"os"

	"github.com/h1s97x/openidp/api/internal/config"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/seed"
	"github.com/h1s97x/openidp/api/internal/timezone"
)

// initdb 初始化数据库：建表（幂等）+ 写入内置种子数据（管理员账号、内置登录提供商）。
//
// 用途：
//   - 测试/CI 环境在启动服务前用该命令独立初始化数据库
//   - 生产环境可通过环境变量 DATABASE_URL 指定 PostgreSQL，初始化后即可接入服务
//
// 环境变量与 api/cmd/server 完全一致（config.FromEnv），可复用：
//
//	DATABASE_URL  空 => SQLite（默认 ./data/openidp.db，DATA_DIR 可覆盖）
//	              非空 => PostgreSQL
//	SEED_USERNAME / SEED_PASSWORD / SEED_EMAIL / SEED_DISPLAY  种子管理员
//	OPENIDP_TIMEZONE  系统时区（默认 Asia/Shanghai，UTC+8）
func main() {
	cfg := config.FromEnv()

	// 与应用主程序使用同一时区口径：种子数据的 created_at/updated_at
	// 按系统时区写入（默认 Asia/Shanghai，可用 OPENIDP_TIMEZONE 指定）。
	if _, err := timezone.Apply(cfg.Timezone); err != nil {
		log.Fatalf("❌ [Timezone] %v", err)
	}

	ctx := context.Background()
	opened, err := db.Open(cfg.DatabaseURL, cfg.DataDir, cfg.DBFallback)
	if err != nil {
		log.Fatalf("❌ [DB] %v", err)
	}
	database := opened.DB
	defer database.Close()
	if opened.Degraded {
		log.Printf("⚠️ [DB] 配置指向 %s，但连接失败，已降级为 SQLite", db.Kind(cfg.DatabaseURL))
	} else {
		log.Printf("✅ [DB] 已连接 %s", opened.Kind)
	}

	if err := db.Migrate(ctx, database); err != nil {
		log.Fatalf("❌ [DB] 建表失败: %v", err)
	}
	log.Printf("📦 [DB] 数据表结构已就绪（%s）", opened.Kind)
	if err := seed.Run(ctx, database, cfg); err != nil {
		log.Fatalf("❌ [Seed] 内置数据初始化失败: %v", err)
	}
	log.Printf("✅ [Seed] 内置数据初始化完成")

	log.Printf("--- 数据库初始化引导程序执行完成 ---")
	log.Printf("✅ 数据库已初始化（实际类型: %s）", opened.Kind)
	if opened.Kind == "sqlite" {
		log.Printf("-> SQLite 文件: %s/openidp.db", cfg.DataDir)
	} else {
		log.Printf("-> 连接串: %s", cfg.DatabaseURL)
	}
	log.Printf("-> 内置登录提供商: 6 个（github/google/microsoft/qq/gitee/linuxdo，默认关闭）")
	log.Printf("-> 管理员账号请在首次启动后通过初始化（setup）页面创建")
	os.Exit(0)
}
