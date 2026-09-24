package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/cache"
	"github.com/h1s97x/openidp/api/internal/config"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/handler"
	"github.com/h1s97x/openidp/api/internal/logging"
	"github.com/h1s97x/openidp/api/internal/middleware"
	"github.com/h1s97x/openidp/api/internal/oidc"
	"github.com/h1s97x/openidp/api/internal/passkey"
	"github.com/h1s97x/openidp/api/internal/scheduler"
	"github.com/h1s97x/openidp/api/internal/seed"
	"github.com/h1s97x/openidp/api/internal/timezone"
	"github.com/h1s97x/openidp/api/internal/version"
)

//go:embed all:dist
var embeddedDist embed.FS

func main() {
	cfg := config.FromEnv()

	// ---- 系统时区：必须在日志初始化之前应用 ----
	// 默认 Asia/Shanghai（UTC+8），可用 OPENIDP_TIMEZONE 指定任意 IANA 时区。
	// 应用后 time.Local 即为系统时区，标准库日志时间戳、按天统计的日界
	// 与前端下发的时间都会以它为准。
	zone, err := timezone.Apply(cfg.Timezone)
	if err != nil {
		// 时区名非法属于配置错误：继续按 UTC 运行会让所有时间展示与统计日界
		// 悄悄错位，因此直接终止启动并提示正确写法。
		fmt.Fprintf(os.Stderr, "❌ [Timezone] %v\n", err)
		os.Exit(1)
	}
	cfg.Timezone = zone.Name

	// ---- 运行日志：先初始化，确保后续所有初始化日志都能落盘 ----
	// 日志目录默认 <DataDir>/log；置为 "-" 或 LOG_FILE_ENABLED=false 则只输出 stderr。
	// 初始化失败（目录不可写等）时降级为仅 stderr，绝不因此阻断启动。
	logDir := filepath.Join(cfg.DataDir, "log")
	if dir := strings.TrimSpace(cfg.LogDir); dir != "" {
		logDir = dir
	}
	if cfg.LogDir == "-" {
		logDir = ""
	}
	closeLog, err := logging.Init(logging.Options{
		Dir:           logDir,
		Enabled:       cfg.LogFileEnabled,
		RetentionDays: cfg.LogRetentionDays,
		MaxSizeMB:     cfg.LogMaxSizeMB,
	})
	if err != nil {
		logging.Warn("⚠️ [Log] 文件日志不可用，日志仅输出到终端：%v", err)
	} else {
		defer closeLog()
		if logDir != "" {
			logging.Info("📝 [Log] 运行日志目录: %s（保留 %d 天，单文件上限 %d MB）", logDir, cfg.LogRetentionDays, cfg.LogMaxSizeMB)
		}
	}

	// 日志级别：debug 会输出访问细节等大量内容，生产建议保持 info。
	logging.SetLevel(logging.ParseLevel(cfg.LogLevel))
	logging.Info("📝 [Log] 日志级别: %s（可用 debug/info/warn/error/off）", logging.GetLevel())
	logging.Info("🕒 [Timezone] 系统时区: %s（%s），日志与界面时间均以此为准", zone.Name, timezone.OffsetLabel())

	v := version.Get()
	logging.Info("========================================")
	logging.Info("🚀 OpenIdP")
	logging.Info("========================================")
	logging.Info("📦 版本: %s", v.Version)
	logging.Info("🔗 Commit: %s", v.Commit)
	logging.Info("📅 构建时间: %s", v.BuildDate)
	logging.Info("🐹 Go 版本: %s", runtime.Version())
	logging.Info("========================================")
	logging.Info("--- 开始初始化核心组件 ---")

	// 应用层加密：密钥首启自动生成并持久化到 DATA_DIR/encryption.key（未配置 ENCRYPTION_KEY 时），
	// 之后的请求重启复用同一密钥，保证已加密数据始终可解密。
	if err := appcrypto.Init(cfg.EncryptionKey, filepath.Join(cfg.DataDir, "encryption.key")); err != nil {
		logging.Fatal("❌ [Secret] 应用层加密初始化失败: %v", err)
	}
	logging.Info("🔐 [Secret] 应用层加密密钥已就绪")

	// 未显式配置 JWT_KEY_DIR 时，默认持久化到 DATA_DIR，避免每次重启导致
	// 全部 access/id token 作废。
	if cfg.JWTKeyDir == "" {
		cfg.JWTKeyDir = filepath.Join(cfg.DataDir, "jwt")
	}

	// 安全提示：显式启用 PostgreSQL 且仍在使用内置默认口令时，提示生产环境务必修改，
	// 避免用可猜测的默认口令（openidp123）暴露到公网。
	if strings.EqualFold(cfg.DatabaseType, "postgres") && cfg.DatabaseURL == "" && cfg.DatabasePassword == config.DefaultDatabasePassword {
		logging.Warn("⚠️ [Config] DATABASE_PASSWORD 仍为内置默认值（%s），生产环境请改成强口令，否则数据库可能被爆破", config.DefaultDatabasePassword)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opened, err := db.Open(cfg.DatabaseURL, cfg.DataDir, cfg.DBFallback)
	if err != nil {
		logging.Fatal("❌ [DB] %v", err)
	}
	database := opened.DB
	defer database.Close()
	if opened.Degraded {
		logging.Warn("⚠️ [DB] 已降级运行：配置指向 %s，实际使用 SQLite（数据目录 %s）", db.Kind(cfg.DatabaseURL), cfg.DataDir)
	} else {
		logging.Info("✅ [DB] 已连接 %s", opened.Kind)
	}

	// 初始化共享缓存（Redis 可用时使用，否则自动降级为内存）。
	// 支撑 TokenStore、限流器、consent 缓存等跨请求共享状态。
	cacheDB, cacheMsg := cache.New(cache.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	logging.Info("💾 [Cache] %s", cacheMsg)
	defer cacheDB.Close()

	if err := db.Migrate(ctx, database); err != nil {
		logging.Fatal("❌ [DB] 建表失败: %v", err)
	}
	logging.Info("📦 [DB] 数据表结构已就绪（%s）", opened.Kind)
	if err := seed.Run(ctx, database, cfg); err != nil {
		logging.Fatal("❌ [Seed] 内置数据初始化失败: %v", err)
	}
	logging.Info("✅ [Seed] 内置数据初始化完成")

	oidcProvider, err := oidc.NewProvider(cfg.JWTKeyDir)
	if err != nil {
		logging.Fatal("❌ [OIDC] 密钥初始化失败: %v", err)
	}
	logging.Info("🔑 [OIDC] JWT 密钥已就绪")

	h := handler.New(database, cfg, oidcProvider, cacheDB)

	// 周期性维护任务：会话/令牌/验证码等过期数据清理、审计日志归档。
	// 由轻量级任务调度器统一管理，替代原先单一的清理协程。
	// 必须在建表（Migrate）之后启动，否则首次启动会打到尚不存在的表而报错。
	sched := scheduler.New()
	sched.Every("cleanup-expired", time.Hour, func(ctx context.Context) error {
		// 审计事件保留期取自管理后台「审计保留策略」（0 = 永久保留）。
		return db.CleanupExpired(ctx, database, h.EventRetentionDays())
	})
	// 审计日志归档：每天把超过保留期的历史事件归档为 JSON 行文件（保留在数据目录）。
	// 未开启归档开关或保留期为 0 时跳过。
	sched.Every("audit-archive", 24*time.Hour, func(ctx context.Context) error {
		a := h.AuditArchivePolicy()
		if !a.ArchiveEnabled {
			return nil
		}
		return db.ArchiveEvents(ctx, database, cfg.DataDir, a.RetentionDays)
	})
	stopSched := sched.Start(ctx)
	defer stopSched()
	logging.Info("⏰ [Task] 已注册周期任务: cleanup-expired, audit-archive")

	// 通行密钥依赖方 URL 按请求动态解析（优先系统设置站点 URL，其次当前访问域名兑底）；
	// 未在系统设置中开启时不启用。
	// 仪式状态存共享缓存（Redis 可用时跨实例共享），多实例下 begin/finish
	// 落在不同实例也能正常完成。
	h.InitPasskeys(passkey.New(database, h.ResolvePasskeyConfig, cacheDB))
	// 仅在系统设置中开启时才输出：未开启时通行密钥实际不可用，
	// 打印"已初始化"会让人误以为功能可用。
	if h.ResolvePasskeyConfig(cfg.SiteURL).Enabled {
		logging.Info("🔐 [Passkey] 通行密钥服务已初始化（系统设置已启用）")
	} else {
		logging.Info("💤 [Passkey] 通行密钥服务已就绪但未启用（可在管理后台开启）")
	}
	// 加载持久化的对象存储配置并重建 Provider（管理后台改动即时生效，无需重启）。
	h.InitStorage()
	logging.Info("💾 [Storage] 存储后端: %s", cfg.StorageBackend)
	// 孤儿文件回收：每天清理已解绑且超过宽限期的文件及其存储对象。
	// 依赖 handler 的存储 Provider，故在 InitStorage 之后注册。
	sched.Every("file-orphan-cleanup", 24*time.Hour, func(ctx context.Context) error {
		deleted, failed := h.CleanupOrphanFiles(ctx)
		if deleted > 0 || failed > 0 {
			logging.Info("🧹 [Storage] 孤儿文件回收完成，已删除 %d 个，失败 %d 个", deleted, failed)
		}
		return nil
	})
	apiHandler := h.Router()

	// 超时配置：只设 ReadHeaderTimeout 时，慢速客户端可以在读完请求头之后
	// 无限缓慢地发送请求体，长期占住连接与 goroutine（Slowloris 类攻击）。
	// 这里把读 / 写 / 空闲 / 头部体积一并限制住。
	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: rootHandler(apiHandler, embeddedDist, cfg.DevFrontendURL,
			rootOptions{
				hsts:       strings.HasPrefix(strings.ToLower(cfg.SiteURL), "https://"),
				cdnBaseURL: cfg.CDNBaseURL,
			}),
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout 覆盖「请求头 + 请求体」的完整读取过程。
		// 取值需容纳最大的上传（附件 10MB）在慢速网络下的传输，故放宽到 5 分钟，
		// 但仍是一个有限值，慢速连接不会无限占用。
		ReadTimeout: 5 * time.Minute,
		// WriteTimeout 覆盖从读完请求头到写完响应的时间。
		// 邮件发送、OIDC 令牌签发等同步操作都在此窗口内完成，留 5 分钟余量。
		// 注意：SSE / WebSocket 类长连接不适用，本项目无此类端点。
		WriteTimeout: 5 * time.Minute,
		// IdleTimeout 是 keep-alive 空闲连接的回收时间：会话轮询间隔远小于它，
		// 正常客户端不受影响，空闲连接则会被及时释放。
		IdleTimeout: 2 * time.Minute,
		// MaxHeaderBytes 限制请求头体积（默认 1MB 偏大，足以被用来放大内存占用）。
		MaxHeaderBytes: 64 << 10,
	}

	go func() {
		// 打印实际生效的数据库类型（可能与配置不同：配置 PG 但已降级 SQLite），
		// 用配置值打印会在降级后严重误导排障。
		logging.Info("--- 核心组件初始化完成 ---")
		logging.Info("🚀 服务已启动，正在监听 %s（数据库: %s）", cfg.Addr, opened.Kind)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logging.Fatal("❌ [HTTP] 监听失败: %v", err)
		}
	}()

	<-ctx.Done()
	logging.Info("--- 收到退出信号，正在关闭服务 ---")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	logging.Info("✅ 服务已安全退出")
}

// rootHandler dispatches API/OIDC paths to the chi router and serves the
// embedded SPA (with index.html fallback) for everything else.
//
// 开发模式（devFrontendURL 非空）下，Go 作为单端口统一入口（默认 :6099）：
// API/OIDC 请求仍由 Go 直接处理，其余页面与静态资源请求全部反向代理到
// Vite dev server（保留 HMR 热更新），与生产内嵌模式行为一致。
//
// CDN 缓存策略（生产内嵌模式）：
//   - /assets/*（Vite 产物带内容哈希）→ 不可变长缓存（public, max-age=31536000, immutable）
//   - /images/logo.svg、/images/avatar.svg 等公开静态资源 → 中时缓存（public, max-age=86400）
//   - index.html / SPA fallback → no-cache（由 CDN 回源，避免引用旧指纹资源）
//   - /api/*、/.well-known/*、/login/oauth/* → 由下面 apiNoStore 明确禁止缓存
//
// rootOptions 是 rootHandler 的行为开关。
type rootOptions struct {
	// hsts 控制是否输出 Strict-Transport-Security。
	hsts bool
	// cdnBaseURL 是前端静态资源 CDN 基址，用于 CSP 白名单。
	cdnBaseURL string
}

func rootHandler(api http.Handler, efs embed.FS, devFrontendURL string, opts rootOptions) http.Handler {
	dist, _ := fs.Sub(efs, "dist")
	fileServer := http.FileServer(http.FS(dist))
	// 开发模式反向代理：仅当显式配置 OPENIDP_DEV_FRONTEND_URL 时启用，生产保持内嵌。
	var devProxy *httputil.ReverseProxy
	if devFrontendURL != "" {
		if u, err := url.Parse(devFrontendURL); err == nil && u.Host != "" {
			devProxy = httputil.NewSingleHostReverseProxy(u)
		}
	}

	// SPA fallback 与 /assets/ 都在 chi 之外直接返回，这里统一包一层，
	// 使全站（含静态资源与用户上传文件）都带 nosniff / CSP / X-Frame-Options。
	// 开发模式必须放开内联脚本：Vite 会向 index.html 注入 react-refresh 引导脚本，
	// 被 CSP 拦掉时页面白屏（模块脚本依赖其注入的全局钩子）。
	secure := middleware.SecurityHeaders(opts.hsts, opts.cdnBaseURL,
		middleware.SecurityOptions{AllowInlineScripts: devProxy != nil})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path

		// API & OIDC paths go to chi router (no-store)
		if p == "/api" || strings.HasPrefix(p, "/api/") ||
			p == "/.well-known" || strings.HasPrefix(p, "/.well-known/") ||
			p == "/login/oauth" || strings.HasPrefix(p, "/login/oauth/") ||
			p == "/api/health" {
			apiNoStore(w)
			api.ServeHTTP(w, r)
			return
		}

		// 静态资源与 SPA fallback 同样输出安全响应头。
		secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveSPA(w, r, dist, fileServer, devProxy)
		})).ServeHTTP(w, r)
	})
}

// serveSPA 提供内嵌前端（或开发模式反向代理）。
func serveSPA(w http.ResponseWriter, r *http.Request, dist fs.FS, fileServer http.Handler, devProxy *httputil.ReverseProxy) {
	p := r.URL.Path
	// 开发模式：非 API 请求全部转发给 Vite dev server（含页面、静态资源、HMR websocket）
	if devProxy != nil {
		devProxy.ServeHTTP(w, r)
		return
	}

	// static assets (real file exists) -> serve file with CDN-friendly headers
	clean := path.Clean("/" + p)
	if info, err := fs.Stat(dist, strings.TrimPrefix(clean, "/")); err == nil && !info.IsDir() {
		if strings.HasPrefix(p, "/assets/") {
			// 内容哈希指纹资源 → 强缓存，CDN 直接命中
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else if strings.HasPrefix(p, "/images/") {
			// 站点图标/静态图片 → 短时缓存
			w.Header().Set("Cache-Control", "public, max-age=86400")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		fileServer.ServeHTTP(w, r)
		return
	}

	// SPA fallback -> index.html (no-cache, 始终回源校验)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	data, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(data)
}

// apiNoStore prevents CDN/proxy caches from serving stale auth responses.
func apiNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}
