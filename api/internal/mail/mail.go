// Package mail implements the email notification system: SMTP transport,
// HTML templates for verification codes (注册/登录/找回密码), customizable
// templates stored in the database (with built-in defaults), and a code store
// that survives restarts via the database.
package mail

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"html"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/h1s97x/openidp/api/internal/logging"
)

// Config is the SMTP / mail configuration.
type Config struct {
	// Enabled gates whether mail sending is turned on (admin switch).
	Enabled  bool
	Host     string
	Port     int
	User     string
	Password string
	From     string
	FromName string
	SiteName string
	SiteURL  string
	// UseTLS enables explicit STARTTLS for ports other than 465.
	UseTLS bool
	// InsecureSkipVerify disables certificate verification (dev/testing only).
	InsecureSkipVerify bool
	// Template is a customizable HTML email template (with {{placeholders}}).
	// Empty means use the built-in default.
	Template string
}

// Sender sends emails.
//
// cfg 用原子指针保存：管理员在后台保存配置（Reconfigure）与并发发信
// （SendCode / Send）会同时发生。此前 cfg 是普通字段、且只有 Reconfigure 加锁，
// 所有读路径都无锁访问——构成数据竞争，极端情况下字段撕裂会把凭据发往错误主机。
type Sender struct {
	cfg atomic.Pointer[Config]
	// storeMu 只用于串行化 Reconfigure 的「读旧值 → 补默认值 → 写回」过程。
	storeMu sync.Mutex
}

// New creates a Sender. When Host is empty it runs in dev mode and logs emails.
// When Config.Enabled was not explicitly set, it is inferred from Host != "".
func New(cfg Config) *Sender {
	if !cfg.Enabled {
		cfg.Enabled = cfg.Host != ""
	}
	if cfg.From == "" {
		cfg.From = "noreply@localhost"
	}
	if cfg.FromName == "" {
		cfg.FromName = cfg.SiteName
	}
	if cfg.SiteName == "" {
		cfg.SiteName = "OpenIdP"
	}
	s := &Sender{}
	s.cfg.Store(&cfg)
	return s
}

// snapshot 返回当前配置的一份值拷贝，供读路径使用。
// 返回拷贝而非指针，避免调用方在并发写发生时读到撕裂的字段。
func (s *Sender) snapshot() Config {
	if c := s.cfg.Load(); c != nil {
		return *c
	}
	return Config{}
}

// Enabled reports whether real SMTP sending is configured and turned on.
func (s *Sender) Enabled() bool {
	c := s.snapshot()
	return c.Enabled && c.Host != ""
}

// Host/Port/From etc. accessors for the admin console.
func (s *Sender) Host() string { return s.snapshot().Host }
func (s *Sender) Port() int    { return s.snapshot().Port }
func (s *Sender) From() string { return s.snapshot().From }
func (s *Sender) FromName() string {
	c := s.snapshot()
	if c.FromName == "" {
		return c.SiteName
	}
	return c.FromName
}
func (s *Sender) UseTLS() bool { return s.snapshot().UseTLS }

// Reconfigure updates the SMTP settings at runtime (used by the admin console).
func (s *Sender) Reconfigure(cfg Config) {
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	old := s.snapshot()
	if cfg.From == "" {
		cfg.From = old.From
	}
	if cfg.FromName == "" {
		cfg.FromName = old.FromName
	}
	if cfg.SiteName == "" {
		cfg.SiteName = old.SiteName
	}
	if cfg.SiteURL == "" {
		cfg.SiteURL = old.SiteURL
	}
	if cfg.Template == "" {
		cfg.Template = old.Template
	}
	s.cfg.Store(&cfg)
}

// TemplateData carries the variables rendered into the email template.
type TemplateData struct {
	SiteName string
	SiteURL  string
	Code     string
	Minutes  int
	Username string
	Action   string // login | signup | reset | change_email | verify_email
	Link     string
}

// SendCode generates a 6-digit code and emails it to the address.
// Returns the code (only useful in dev mode / for tests). 验证码本身统一持久化到
// 数据库（verification_codes），内存中不做任何缓存（无需为历史数据兜底）。
// siteURL 为可选覆盖项：非空时作为邮件内链接的站点地址（支持按请求域名动态推导），
// 为空时使用启动配置的 SiteURL。
func (s *Sender) SendCode(to, purpose string, minutes int, siteURL ...string) (string, error) {
	code := randomCode(6)

	actionLabel := map[string]string{
		"login":        "登录",
		"signup":       "注册",
		"reset":        "重置密码",
		"change_email": "更换邮箱",
		"verify_email": "验证邮箱",
	}[purpose]
	if actionLabel == "" {
		actionLabel = purpose
	}
	// 一次取快照，整封邮件都用同一份配置渲染，避免中途配置被改写导致主题与正文不一致。
	c := s.snapshot()
	base := c.SiteURL
	if len(siteURL) > 0 && strings.TrimSpace(siteURL[0]) != "" {
		base = siteURL[0]
	}
	data := TemplateData{
		SiteName: c.SiteName,
		SiteURL:  base,
		Code:     code,
		Minutes:  minutes,
		Action:   actionLabel,
	}
	subject := fmt.Sprintf("【%s】%s验证码：%s", c.SiteName, actionLabel, code)
	body := renderTemplate(data, c.Template)
	return code, s.Send(to, subject, body)
}

// SendVerifyLink sends an email-verification link (令牌方式，区别于 6 位验证码)。
// token 由调用方生成并持久化，邮件中的链接会携带该 token。
// siteURL 为可选覆盖项：非空时作为邮件内链接的站点地址（支持按请求域名动态推导）。
func (s *Sender) SendVerifyLink(to, username, token string, siteURL ...string) error {
	c := s.snapshot()
	base := c.SiteURL
	if len(siteURL) > 0 && strings.TrimSpace(siteURL[0]) != "" {
		base = siteURL[0]
	}
	data := TemplateData{
		SiteName: c.SiteName,
		SiteURL:  base,
		Username: username,
		Action:   "验证邮箱",
		Link:     strings.TrimRight(base, "/") + "/verify-email?token=" + token,
	}
	subject := fmt.Sprintf("【%s】请验证您的邮箱", c.SiteName)
	body := renderTemplate(data, c.Template)
	return s.Send(to, subject, body)
}

// SendTest sends a test email to the given address and returns an error if any.
func (s *Sender) SendTest(to string) error {
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("empty recipient")
	}
	c := s.snapshot()
	subject := fmt.Sprintf("【%s】测试邮件", c.SiteName)
	body := renderTestTemplate(c.SiteName, c.SiteURL, c.Template)
	return s.Send(to, subject, body)
}

// Send sends an HTML email.
func (s *Sender) Send(to, subject, htmlBody string) error {
	if !s.Enabled() {
		// dev mode: 未配置 SMTP 时把验证码打到日志，开发者可直接读取。
		//
		// 使用 logging.Sensitive 而非 log.Printf：邮件正文含登录/注册验证码，
		// 属于可直接用于登录的有效凭据。若写入日志文件，等于把凭据留在磁盘上，
		// 且随日志备份一起扩散。因此这类内容只输出终端，不落盘。
		logging.Sensitive("📧 [Mail] 开发模式邮件预览（未配置 SMTP）-> 收件人: %s | 主题: %s", to, subject)
		logging.Sensitive("📄 [Mail] 正文:\n%s", htmlBody)
		return nil
	}
	return s.sendSMTP(to, subject, htmlBody)
}

func (s *Sender) sendSMTP(to, subject, htmlBody string) error {
	// 整封邮件只取一次配置快照：主机、端口、凭据必须来自同一份配置，
	// 否则并发改写时可能出现「用 A 主机的凭据连 B 主机」的字段撕裂。
	c := s.snapshot()
	// 过滤 FromName 中的 CR/LF，防止管理员配置注入伪造邮件头（header injection）。
	from := fmt.Sprintf("%s <%s>", sanitizeHeaderValue(c.FromName), c.From)
	subject = sanitizeHeaderValue(subject)
	msg := strings.Builder{}
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: base64\r\n")
	fmt.Fprintf(&msg, "From: %s\r\n", from)
	fmt.Fprintf(&msg, "To: <%s>\r\n", sanitizeHeaderValue(to))
	fmt.Fprintf(&msg, "Subject: =?UTF-8?B?%s?=\r\n", base64.StdEncoding.EncodeToString([]byte(subject)))
	msg.WriteString("\r\n")
	msg.WriteString(base64.StdEncoding.EncodeToString([]byte(htmlBody)))

	addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
	var auth smtp.Auth
	if c.User != "" {
		auth = smtp.PlainAuth("", c.User, c.Password, c.Host)
	}
	// implicit TLS (SMTPS, usually 465)
	if c.Port == 465 {
		return smtpSend(addr, auth, c.From, []string{to}, []byte(msg.String()), c.InsecureSkipVerify, true)
	}
	if c.UseTLS {
		return smtpSend(addr, auth, c.From, []string{to}, []byte(msg.String()), c.InsecureSkipVerify, false)
	}
	return smtp.SendMail(addr, auth, c.From, []string{to}, []byte(msg.String()))
}

// smtpSend 发送邮件：implicitTLS=true 走 SMTPS（端口 465），false 走 STARTTLS 升级。
func smtpSend(addr string, auth smtp.Auth, from string, to []string, body []byte, skipVerify bool, implicitTLS bool) error {
	host := hostOnly(addr)
	tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify}

	var (
		conn net.Conn
		err  error
	)
	if implicitTLS {
		conn, err = tls.Dial("tcp", addr, tlsCfg)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	if !implicitTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return err
			}
		}
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// sanitizeHeaderValue strips CR/LF from a value before it is placed into an
// email header, preventing header/response splitting via crafted FromName or
// Subject (which may originate from admin configuration).
func sanitizeHeaderValue(v string) string {
	v = strings.ReplaceAll(v, "\r", " ")
	v = strings.ReplaceAll(v, "\n", " ")
	return v
}

// renderTemplate renders the code template. When a custom template is
// provided it is used verbatim; otherwise the built-in default is used.
func renderTemplate(d TemplateData, custom string) string {
	code := html.EscapeString(d.Code)
	site := html.EscapeString(d.SiteName)
	siteURL := html.EscapeString(d.SiteURL)
	action := html.EscapeString(d.Action)
	username := html.EscapeString(d.Username)
	if username == "" {
		username = "用户"
	}
	if strings.TrimSpace(custom) != "" {
		replacer := strings.NewReplacer(
			"{{siteName}}", site,
			"{{siteUrl}}", siteURL,
			"{{code}}", code,
			"{{action}}", action,
			"{{username}}", username,
			"{{minutes}}", fmt.Sprintf("%d", d.Minutes),
			"{{link}}", html.EscapeString(d.Link),
		)
		return replacer.Replace(custom)
	}
	// 内置默认模板：验证码邮件。含链接时展示按钮（验证邮箱场景）。
	if d.Link != "" {
		return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif">
  <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:32px 16px">
    <tr><td align="center">
      <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.06)">
        <tr><td style="background:linear-gradient(135deg,#3ea4ec,#0276ea);padding:28px 32px">
          <div style="color:#fff;font-size:20px;font-weight:600">%s</div>
          <div style="color:rgba(255,255,255,.8);font-size:13px;margin-top:4px">身份验证 · 安全通知</div>
        </td></tr>
        <tr><td style="padding:32px">
          <div style="font-size:15px;color:#0a0a0a;line-height:1.7">%s，您好：</div>
          <div style="font-size:15px;color:#0a0a0a;line-height:1.7;margin-top:12px">您正在请求进行<span style="color:#0276ea;font-weight:600">%s</span>。点击下方按钮完成操作：</div>
          <div style="margin:24px 0;text-align:center">
            <a href="%s" style="display:inline-block;padding:12px 32px;background:#0276ea;color:#fff;border-radius:8px;font-size:15px;font-weight:600;text-decoration:none">立即验证</a>
          </div>
          <div style="font-size:13px;color:#606060;line-height:1.7">如果按钮无法点击，请复制以下链接到浏览器打开：<br><span style="word-break:break-all">%s</span></div>
          <div style="margin-top:24px;padding-top:20px;border-top:1px solid #e8e8e8;font-size:12px;color:#8a8a8a">此邮件由 <a href="%s" style="color:#0276ea">%s</a> 自动发送，请勿直接回复。</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`, site, username, action, html.EscapeString(d.Link), html.EscapeString(d.Link), siteURL, site)
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif">
  <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:32px 16px">
    <tr><td align="center">
      <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.06)">
        <tr><td style="background:linear-gradient(135deg,#3ea4ec,#0276ea);padding:28px 32px">
          <div style="color:#fff;font-size:20px;font-weight:600">%s</div>
          <div style="color:rgba(255,255,255,.8);font-size:13px;margin-top:4px">身份验证 · 安全通知</div>
        </td></tr>
        <tr><td style="padding:32px">
          <div style="font-size:15px;color:#0a0a0a;line-height:1.7">%s，您好：</div>
          <div style="font-size:15px;color:#0a0a0a;line-height:1.7;margin-top:12px">您正在请求进行<span style="color:#0276ea;font-weight:600">%s</span>。本次验证码为：</div>
          <div style="margin:24px 0;text-align:center">
            <span style="display:inline-block;padding:14px 36px;background:#eaf4fe;border:1px dashed #8ec9f5;border-radius:10px;font-size:28px;font-weight:700;letter-spacing:8px;color:#0276ea">%s</span>
          </div>
          <div style="font-size:13px;color:#606060;line-height:1.7">验证码 %d 分钟内有效。若非本人操作，请忽略本邮件并检查账户安全。</div>
          <div style="margin-top:24px;padding-top:20px;border-top:1px solid #e8e8e8;font-size:12px;color:#8a8a8a">此邮件由 <a href="%s" style="color:#0276ea">%s</a> 自动发送，请勿直接回复。</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`, site, username, action, code, d.Minutes, siteURL, site)
}

// renderTestTemplate renders the built-in test mail body (or a custom template
// when one is configured).
func renderTestTemplate(siteName, siteURL, custom string) string {
	if strings.TrimSpace(custom) != "" {
		replacer := strings.NewReplacer(
			"{{siteName}}", html.EscapeString(siteName),
			"{{siteUrl}}", html.EscapeString(siteURL),
			"{{code}}", "123456",
			"{{action}}", "测试",
			"{{username}}", "用户",
			"{{minutes}}", "10",
		)
		return replacer.Replace(custom)
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif">
  <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:32px 16px">
    <tr><td align="center">
      <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.06)">
        <tr><td style="background:linear-gradient(135deg,#009966,#0084d1);padding:28px 32px">
          <div style="color:#fff;font-size:20px;font-weight:600">%s</div>
          <div style="color:rgba(255,255,255,.8);font-size:13px;margin-top:4px">邮件服务测试</div>
        </td></tr>
        <tr><td style="padding:32px">
          <div style="font-size:15px;color:#0a0a0a;line-height:1.7">这封测试邮件表明 <a href="%s" style="color:#009966">%s</a> 的 SMTP 邮件服务配置正确、可以正常投递。</div>
          <div style="margin-top:16px;font-size:13px;color:#606060">如果你收到了本邮件，说明邮件通道已经打通，验证码与通知邮件都将通过该通道发送。</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`, html.EscapeString(siteName), html.EscapeString(siteURL), html.EscapeString(siteName))
}

// DefaultTemplate returns the built-in verification-code template (for the admin UI).
func DefaultTemplate() string {
	d := TemplateData{SiteName: "{{siteName}}", SiteURL: "{{siteUrl}}", Code: "{{code}}", Minutes: 10, Username: "{{username}}", Action: "{{action}}"}
	return renderTemplate(d, "")
}

// randomCode 生成 n 位数字验证码。
//
// 用 crypto/rand 逐位取 0-9 并在超界时重采，而不是对整个字节取模：
// 256 不是 10 的整数倍，`b % 10` 会让 0-5 的出现概率略高于 6-9（模偏差），
// 虽影响很小，但验证码本应均匀随机，重采样是零成本的正确做法。
func randomCode(n int) string {
	const digits = "0123456789"
	var sb strings.Builder
	sb.Grow(n)
	buf := make([]byte, 1)
	for i := 0; i < n; i++ {
		// 拒绝采样：只接受 < 250（10 的最大整数倍 ≤ 255）的字节。
		for {
			if _, err := rand.Read(buf); err != nil {
				panic(err)
			}
			if buf[0] < 250 {
				break
			}
		}
		sb.WriteByte(digits[int(buf[0])%len(digits)])
	}
	return sb.String()
}
