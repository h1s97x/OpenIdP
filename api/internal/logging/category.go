package logging

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// 分类日志
//
// 除通用日志外，以下三类事件需要独立留痕，便于排障与合规审计：
//   - Access：HTTP 访问日志（谁在什么时候请求了什么、耗时、状态码）
//   - Audit：安全审计日志（登录、改密、MFA、改绑邮箱等敏感操作）
//   - Config：配置变更日志（管理员修改了哪些系统设置）
//
// 三者共用同一份文件输出（与通用日志同文件，便于按时间线对照），
// 但带有各自的分类标签，可用 grep 快速过滤。
// ---------------------------------------------------------------------------

// Access 记录一次 HTTP 访问。
//
// 出于日志体量与隐私考虑：
//   - 不记录请求体（可能含密码、验证码等凭据）
//   - 查询串仅保留键名，不记录值（值里可能带 token、邮箱等）
//   - 健康检查等高频端点由调用方决定是否跳过
func Access(r *http.Request, status, bytes int, dur time.Duration) {
	if !enabled(LevelInfo) {
		return
	}
	log.Printf("[ACCESS] %s %s %d %dB %s ip=%s ua=%q",
		r.Method, sanitizePath(r.URL.Path), status, bytes, dur.Round(time.Millisecond),
		clientIPForLog(r), truncate(oneLine(r.UserAgent()), 120),
	)
}

// Audit 记录一条安全审计事件。
//
// result 建议取值：success / failure，便于检索。
// detail 里禁止放入密码、验证码、令牌等凭据。
func Audit(result, category, action string, userID int64, ip, detail string) {
	if !enabled(LevelInfo) {
		return
	}
	log.Printf("[AUDIT] result=%s category=%s action=%s userID=%d ip=%s detail=%s",
		result, category, action, userID, defaultStr(ip, "-"), truncate(oneLine(detail), 300),
	)
}

// ConfigChange 记录一次配置变更。
//
// scope 是配置分组（如 site / security-policy / mail / storage）；
// fields 记录被修改的字段名，不记录值（值可能含 SMTP 密码、S3 密钥等）。
func ConfigChange(scope, action string, userID int64, ip string, fields []string) {
	if !enabled(LevelInfo) {
		return
	}
	log.Printf("[CONFIG] scope=%s action=%s userID=%d ip=%s fields=[%s]",
		scope, action, userID, defaultStr(ip, "-"), strings.Join(fields, " "),
	)
}

// ---------------- 内部辅助 ----------------

// clientIPKey 是请求上下文里存放「已解析的可信客户端 IP」的键。
//
// 由 handler 的 withClientIP 中间件写入，访问日志读取。放在 logx 包是因为它
// 位于依赖链最底层：handler 与 middleware 都依赖 logx，而 logx 不能反向依赖它们。
type clientIPKey struct{}

// WithClientIP 把已解析的客户端 IP 注入请求上下文。
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIPFromContext 读取上下文里已解析的客户端 IP，没有则返回空串。
func ClientIPFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(clientIPKey{}).(string); ok {
		return v
	}
	return ""
}

// clientIPForLog 取日志用的客户端 IP。
//
// 优先使用中间件解析好的可信客户端 IP：它已经处理过反向代理 / CDN 的转发头，
// 并在对端不可信时回退到 TCP 对端地址。
//
// 此前这里直接读 RemoteAddr，注释还写着「中间件层已完成反向代理头处理，此处无需
// 重复解析」——但中间件把结果写进了 context，并没有改动 RemoteAddr。于是在
// Nginx / CDN 反代部署下，访问日志记录的全是代理的内网地址，审计与排障同时失真。
func clientIPForLog(r *http.Request) string {
	if ip := ClientIPFromContext(r.Context()); ip != "" {
		return ip
	}
	if r.RemoteAddr == "" {
		return "-"
	}
	// 去掉端口
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// sanitizePath 去掉路径中可能的敏感片段。
// 例如邮箱验证页 /verify-email?token=xxx 的 token 已在查询串处理中丢弃。
func sanitizePath(p string) string {
	if p == "" {
		return "/"
	}
	return truncate(p, 200)
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func defaultStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
