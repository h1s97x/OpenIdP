package seed

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/config"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/oauth2"
	"github.com/h1s97x/openidp/api/internal/timezone"
)

// defaultProviders are the login providers shown on the sign-in page.
// 内置 6 家社交登录：GitHub / Google / 微软 / QQ / Gitee / LinuxDo。
// 6 家 Logo 为用户提供的官方素材（矢量 SVG，已内置到 web/public/images/providers/）。
//
// 端点（授权 / 令牌 / 用户信息 / openid / Scope / 文档）取自 oauth2 注册表，
// 由 builtinEndpoints 在初始化时一并写入数据库：后台可直接查看与修改，
// 运行期以数据库取值为准，未改动过的内置提供商与历史行为完全一致。
var defaultProviders = []models.OAuthProvider{
	{ID: "prov_github", Name: "Oauth-github", DisplayName: "Github", ProviderType: "github", LogoURL: "/images/providers/github.svg", Enabled: false},
	{ID: "prov_google", Name: "Oauth-google", DisplayName: "Google", ProviderType: "google", LogoURL: "/images/providers/google.svg", Enabled: false},
	{ID: "prov_microsoft", Name: "Oauth-microsoft", DisplayName: "Microsoft", ProviderType: "microsoft", LogoURL: "/images/providers/microsoft.svg", Enabled: false},
	{ID: "prov_qq", Name: "Oauth-QQ", DisplayName: "QQ", ProviderType: "qq", LogoURL: "/images/providers/qq.svg", Enabled: false},
	{ID: "prov_gitee", Name: "Oauth-Gitee", DisplayName: "Gitee", ProviderType: "gitee", LogoURL: "/images/providers/gitee.svg", Enabled: false},
	{ID: "prov_linuxdo", Name: "Oauth-Linuxdo", DisplayName: "LinuxDo", ProviderType: "linuxdo", LogoURL: "/images/providers/linuxdo.svg", Enabled: false},
}

// builtinEndpoints 返回内置注册表里该提供商的端点配置（未内置时返回 false）。
// 初始化写入与「清空端点后回落默认」共用这一份取值，避免两处漂移。
func builtinEndpoints(providerType string) (models.OAuthProvider, bool) {
	def, ok := oauth2.Get(providerType)
	if !ok {
		return models.OAuthProvider{}, false
	}
	return models.OAuthProvider{
		AuthorizeURL: def.AuthorizeURL,
		TokenURL:     def.TokenURL,
		UserInfoURL:  def.UserInfoURL,
		OpenIDURL:    def.OpenIDURL,
		Scopes:       def.Scopes,
		DocsURL:      def.DocsURL,
	}, true
}

// Run seeds the default providers + applies env-provided OAuth credentials if
// absent (idempotent). 项目初始化时不再自动内置账号，管理员账号在首次部署时通过
// 初始化（setup）页面创建。
func Run(ctx context.Context, db *bun.DB, cfg *config.Config) error {
	if err := seedProviders(ctx, db, cfg); err != nil {
		return err
	}
	if err := seedSecurityPolicy(ctx, db); err != nil {
		return err
	}
	return nil
}

// seedProviders seeds the built-in OAuth providers if the table is empty.
// 已存在时同步内置 Logo、补齐缺省端点；Env 提供的 ClientID/Secret 会写入，方便快速接入。
func seedProviders(ctx context.Context, db *bun.DB, cfg *config.Config) error {
	count, err := db.NewSelect().Model((*models.OAuthProvider)(nil)).Count(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		// 已存在时：同步内置 Logo 地址（便于用户提供的官方素材生效）
		for i := range defaultProviders {
			p := &defaultProviders[i]
			if cid := cfg.ProviderClientIDs[p.ProviderType]; cid != "" {
				_, _ = db.NewUpdate().Model((*models.OAuthProvider)(nil)).
					Set("client_id = ?", cid).
					Where("id = ?", p.ID).Exec(ctx)
			}
			if csec := cfg.ProviderClientSecrets[p.ProviderType]; csec != "" {
				_, _ = db.NewUpdate().Model((*models.OAuthProvider)(nil)).
					Set("client_secret = ?", appcrypto.Encrypt(csec)).
					Where("id = ?", p.ID).Exec(ctx)
			}
			// 同步内置 Logo（便于用户提供的官方素材生效）
			_, _ = db.NewUpdate().Model((*models.OAuthProvider)(nil)).
				Set("logo_url = ?", p.LogoURL).
				Where("id = ?", p.ID).Exec(ctx)
			// 补齐端点：仅当端点列仍为空时写入内置默认值。
			// 一旦管理员在后台改过端点，这里就不再覆盖——否则每次启动都会把
			// 管理员的改动悄悄还原成内置值。
			if err := backfillProviderEndpoints(ctx, db, p.ID, p.ProviderType); err != nil {
				return err
			}
		}
		return nil
	}
	now := timezone.Now()
	for i := range defaultProviders {
		p := &defaultProviders[i]
		p.CreatedAt = now
		if cid := cfg.ProviderClientIDs[p.ProviderType]; cid != "" {
			p.ClientID = cid
		}
		if csec := cfg.ProviderClientSecrets[p.ProviderType]; csec != "" {
			p.ClientSecret = appcrypto.Encrypt(csec)
		}
		if p.ClientID != "" && p.ClientSecret != "" {
			p.Enabled = true
		}
		// 内置端点随行一起写入：后台「登录提供商」里可直接查看与修改，
		// 无需再去翻代码或官方文档。
		if def, ok := builtinEndpoints(p.ProviderType); ok {
			p.AuthorizeURL = def.AuthorizeURL
			p.TokenURL = def.TokenURL
			p.UserInfoURL = def.UserInfoURL
			p.OpenIDURL = def.OpenIDURL
			p.Scopes = def.Scopes
			p.DocsURL = def.DocsURL
		}
		if _, err := db.NewInsert().Model(p).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// backfillProviderEndpoints 为「端点尚未落库」的内置提供商补齐内置默认端点。
//
// 场景：数据库由旧版本建表，oauth_providers 的端点列虽然存在但全是空串——
// 此时后台看不到端点、也无从修改。这里按列补齐，已有取值的列一律不动，
// 保证管理员改过的端点不会被启动流程覆盖。
func backfillProviderEndpoints(ctx context.Context, db *bun.DB, id, providerType string) error {
	def, ok := builtinEndpoints(providerType)
	if !ok {
		return nil
	}
	var cur models.OAuthProvider
	if err := db.NewSelect().Model(&cur).Where("id = ?", id).Scan(ctx); err != nil {
		// 该行不存在属正常情况：库里可能只有部分内置提供商（删过记录、
		// 或来自更早的版本）。没有行就没有需要补的端点，不能因此阻断启动。
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	upd := db.NewUpdate().Model((*models.OAuthProvider)(nil)).Where("id = ?", id)
	changed := false
	setIfEmpty := func(col, cur, def string) {
		if strings.TrimSpace(cur) == "" && strings.TrimSpace(def) != "" {
			upd = upd.Set(col+" = ?", def)
			changed = true
		}
	}
	setIfEmpty("authorize_url", cur.AuthorizeURL, def.AuthorizeURL)
	setIfEmpty("token_url", cur.TokenURL, def.TokenURL)
	setIfEmpty("user_info_url", cur.UserInfoURL, def.UserInfoURL)
	setIfEmpty("open_id_url", cur.OpenIDURL, def.OpenIDURL)
	setIfEmpty("docs_url", cur.DocsURL, def.DocsURL)
	if len(cur.Scopes) == 0 && len(def.Scopes) > 0 {
		upd = upd.Set("scopes = ?", def.Scopes)
		changed = true
	}
	if !changed {
		return nil
	}
	_, err := upd.Exec(ctx)
	return err
}

// seedSecurityPolicy seeds the single-row default security policy if absent.
func seedSecurityPolicy(ctx context.Context, db *bun.DB) error {
	count, err := db.NewSelect().Model((*models.SecurityPolicy)(nil)).Count(ctx)
	if err != nil {
		return fmt.Errorf("count security policy: %w", err)
	}
	if count > 0 {
		return nil
	}
	// 密码登录默认开启；管理后台已隐藏该开关，故初始化即为开启状态。
	sp := &models.SecurityPolicy{
		ID:                   1,
		MinPasswordLength:    8,
		RequireUppercase:     false,
		RequireLowercase:     false,
		RequireNumber:        false,
		RequireSymbol:        false,
		SessionTTLDays:       14,
		PasswordResetEnabled: true,
		// 开放注册默认关闭：全新部署不应在管理员决策前对外敞开注册入口。
		SignupEnabled:           false,
		SignupEmailVerification: true,
		PasswordLoginEnabled:    true,
		UpdatedAt:               timezone.Now(),
	}
	if _, err := db.NewInsert().Model(sp).Exec(ctx); err != nil {
		return fmt.Errorf("seed security policy: %w", err)
	}
	return nil
}
