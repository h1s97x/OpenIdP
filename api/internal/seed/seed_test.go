package seed

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"

	"github.com/h1s97x/openidp/api/internal/appcrypto"
	"github.com/h1s97x/openidp/api/internal/config"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
	"github.com/h1s97x/openidp/api/internal/oauth2"
	"github.com/h1s97x/openidp/api/internal/timezone"
)

// ---------------------------------------------------------------------------
// 内置数据初始化测试。
//
// 背景：seed 包此前零测试。它负责写入内置登录提供商与安全策略单行记录，
// 是每次启动都会执行的代码路径（必须幂等）。若不再幂等，重启就会报错或
// 产生重复数据。
// ---------------------------------------------------------------------------

func newSeedTestDB(t *testing.T) *bun.DB {
	t.Helper()
	dir := t.TempDir()
	sqldb, err := sql.Open(sqliteshim.DriverName(),
		"file:"+filepath.Join(dir, "t.db")+"?cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	bdb := bun.NewDB(sqldb, sqlitedialect.New())
	t.Cleanup(func() { _ = bdb.Close() })
	if err := db.Migrate(context.Background(), bdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return bdb
}

// TestRunIsIdempotent 连续多次执行不应报错，也不应产生重复数据。
// 服务每次启动都会调用 Run，这是最重要的契约。
func TestRunIsIdempotent(t *testing.T) {
	bdb := newSeedTestDB(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := Run(ctx, bdb, &config.Config{}); err != nil {
			t.Fatalf("Run #%d failed: %v", i+1, err)
		}
	}

	// 提供商数量应等于内置列表长度，不因重复执行而增长
	pc, err := bdb.NewSelect().Model((*models.OAuthProvider)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("count providers: %v", err)
	}
	if pc != len(defaultProviders) {
		t.Errorf("提供商数 = %d, want %d（重复执行产生了重复数据）", pc, len(defaultProviders))
	}

	// 安全策略应只有一行
	sc, err := bdb.NewSelect().Model((*models.SecurityPolicy)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("count security policy: %v", err)
	}
	if sc != 1 {
		t.Errorf("安全策略行数 = %d, want 1", sc)
	}
}

// TestRunSeedsProviders 首次运行应写入全部内置提供商，且默认关闭。
func TestRunSeedsProviders(t *testing.T) {
	bdb := newSeedTestDB(t)
	ctx := context.Background()
	if err := Run(ctx, bdb, &config.Config{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var providers []models.OAuthProvider
	if err := bdb.NewSelect().Model(&providers).Scan(ctx, &providers); err != nil {
		t.Fatalf("load providers: %v", err)
	}
	if len(providers) != len(defaultProviders) {
		t.Fatalf("提供商数 = %d, want %d", len(providers), len(defaultProviders))
	}
	// 默认必须关闭：否则未配置凭据的提供商会出现在登录页上，点击必然失败
	for _, p := range providers {
		if p.Enabled {
			t.Errorf("提供商 %q 默认应为关闭", p.ProviderType)
		}
		if p.LogoURL == "" {
			t.Errorf("提供商 %q 缺少 LogoURL", p.ProviderType)
		}
	}
}

// TestRunSeedsSecurityPolicy 安全策略应有合理默认值：
// 密码登录默认开启（否则未配置三方登录时无法登录）。
func TestRunSeedsSecurityPolicy(t *testing.T) {
	bdb := newSeedTestDB(t)
	ctx := context.Background()
	if err := Run(ctx, bdb, &config.Config{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var pol models.SecurityPolicy
	if err := bdb.NewSelect().Model(&pol).Scan(ctx); err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if !pol.PasswordLoginEnabled {
		t.Error("密码登录默认应开启，否则初次部署无法登录")
	}
}

// TestRunAppliesEnvCredentials 环境变量提供凭据时应写入对应提供商。
// ProviderClientIDs/Secrets 的键必须与 ProviderType 一致。
func TestRunAppliesEnvCredentials(t *testing.T) {
	// 应用层加密需先初始化，否则 appcrypto.Encrypt 是直通的（未配置密钥时的降级行为），
	// 那样就无法验证"密钥不以明文存储"这一契约。
	dir := t.TempDir()
	if err := appcrypto.Init("", filepath.Join(dir, "enc.key")); err != nil {
		t.Fatalf("secret init: %v", err)
	}

	bdb := newSeedTestDB(t)
	ctx := context.Background()
	cfg := &config.Config{
		ProviderClientIDs:     map[string]string{"github": "gh-id"},
		ProviderClientSecrets: map[string]string{"github": "gh-secret"},
	}
	if err := Run(ctx, bdb, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var p models.OAuthProvider
	if err := bdb.NewSelect().Model(&p).Where("provider_type = ?", "github").Scan(ctx); err != nil {
		t.Fatalf("load github provider: %v", err)
	}
	if p.ClientID != "gh-id" {
		t.Errorf("ClientID = %q, want gh-id", p.ClientID)
	}
	if p.ClientSecret == "" {
		t.Error("ClientSecret 应已写入（加密存储，故不比对明文）")
	}
	// 密钥必须是加密后的密文，不能是明文（防止数据库泄露即泄露密钥）
	if p.ClientSecret == "gh-secret" {
		t.Error("ClientSecret 不应以明文存储")
	}
}

// TestRunSeedsBuiltinEndpoints 回归：初始化时把内置端点一并写入数据库，
// 后台才能看到并可修改这些端点（此前端点只存在于代码里）。
func TestRunSeedsBuiltinEndpoints(t *testing.T) {
	bdb := newSeedTestDB(t)
	ctx := context.Background()
	if err := Run(ctx, bdb, &config.Config{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var providers []models.OAuthProvider
	if err := bdb.NewSelect().Model(&providers).Scan(ctx, &providers); err != nil {
		t.Fatalf("load providers: %v", err)
	}
	if len(providers) == 0 {
		t.Fatal("未写入任何内置提供商")
	}
	for _, p := range providers {
		def, ok := oauth2.Get(p.ProviderType)
		if !ok {
			continue
		}
		if p.AuthorizeURL != def.AuthorizeURL {
			t.Errorf("%s: authorize_url = %q, want %q", p.ProviderType, p.AuthorizeURL, def.AuthorizeURL)
		}
		if p.TokenURL != def.TokenURL {
			t.Errorf("%s: token_url = %q, want %q", p.ProviderType, p.TokenURL, def.TokenURL)
		}
		if p.UserInfoURL != def.UserInfoURL {
			t.Errorf("%s: user_info_url = %q, want %q", p.ProviderType, p.UserInfoURL, def.UserInfoURL)
		}
		if p.OpenIDURL != def.OpenIDURL {
			t.Errorf("%s: open_id_url = %q, want %q", p.ProviderType, p.OpenIDURL, def.OpenIDURL)
		}
		if strings.Join(p.Scopes, " ") != strings.Join(def.Scopes, " ") {
			t.Errorf("%s: scopes = %v, want %v", p.ProviderType, p.Scopes, def.Scopes)
		}
	}
	// QQ 依赖 /oauth2.0/me 换取 openid，该端点必须落库，否则后台改不到它。
	var qq models.OAuthProvider
	if err := bdb.NewSelect().Model(&qq).Where("provider_type = ?", "qq").Scan(ctx); err != nil {
		t.Fatalf("load qq: %v", err)
	}
	if qq.OpenIDURL == "" {
		t.Error("QQ 的 openid 端点必须落库")
	}
}

// TestRunDoesNotOverwriteAdminEditedEndpoints 回归：端点一旦被管理员改过，
// 重复执行初始化不得把它还原成内置默认值——否则每次重启都会悄悄丢掉改动。
func TestRunDoesNotOverwriteAdminEditedEndpoints(t *testing.T) {
	bdb := newSeedTestDB(t)
	ctx := context.Background()
	if err := Run(ctx, bdb, &config.Config{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	custom := "https://idp.internal.example.com/oauth/authorize"
	if _, err := bdb.NewUpdate().Model((*models.OAuthProvider)(nil)).
		Set("authorize_url = ?", custom).
		Where("provider_type = ?", "github").Exec(ctx); err != nil {
		t.Fatalf("simulate admin edit: %v", err)
	}

	// 再跑两次初始化（模拟服务重启）。
	for i := 0; i < 2; i++ {
		if err := Run(ctx, bdb, &config.Config{}); err != nil {
			t.Fatalf("Run #%d: %v", i+2, err)
		}
	}

	var p models.OAuthProvider
	if err := bdb.NewSelect().Model(&p).Where("provider_type = ?", "github").Scan(ctx); err != nil {
		t.Fatalf("load github: %v", err)
	}
	if p.AuthorizeURL != custom {
		t.Errorf("管理员改动被初始化流程覆盖：authorize_url = %q, want %q", p.AuthorizeURL, custom)
	}
}

// TestRunBackfillsMissingEndpointsForLegacyDB 旧库升级场景：端点为空的
// 内置提供商应在启动时补齐内置默认值，否则后台看不到端点、也无从修改。
func TestRunBackfillsMissingEndpointsForLegacyDB(t *testing.T) {
	bdb := newSeedTestDB(t)
	ctx := context.Background()

	// 模拟旧版本写入的记录：端点列全为空。
	now := timezone.Now()
	legacy := &models.OAuthProvider{
		ID: "prov_github", Name: "Oauth-github", DisplayName: "Github",
		ProviderType: "github", LogoURL: "/images/providers/github.svg",
		Enabled: false, CreatedAt: now,
	}
	if _, err := bdb.NewInsert().Model(legacy).Exec(ctx); err != nil {
		t.Fatalf("insert legacy provider: %v", err)
	}

	if err := Run(ctx, bdb, &config.Config{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var p models.OAuthProvider
	if err := bdb.NewSelect().Model(&p).Where("provider_type = ?", "github").Scan(ctx); err != nil {
		t.Fatalf("load github: %v", err)
	}
	def, _ := oauth2.Get("github")
	if p.AuthorizeURL != def.AuthorizeURL {
		t.Errorf("旧库端点未补齐：authorize_url = %q, want %q", p.AuthorizeURL, def.AuthorizeURL)
	}
	if p.TokenURL != def.TokenURL {
		t.Errorf("旧库端点未补齐：token_url = %q, want %q", p.TokenURL, def.TokenURL)
	}
	if p.UserInfoURL != def.UserInfoURL {
		t.Errorf("旧库端点未补齐：user_info_url = %q, want %q", p.UserInfoURL, def.UserInfoURL)
	}
	if len(p.Scopes) == 0 {
		t.Error("旧库的 scopes 应被补齐")
	}
}

// TestBuiltinEndpointsMatchRegistry 内置端点取值必须来自注册表，两处不得漂移。
func TestBuiltinEndpointsMatchRegistry(t *testing.T) {
	for _, p := range defaultProviders {
		got, ok := builtinEndpoints(p.ProviderType)
		if !ok {
			t.Errorf("%q 不在内置注册表中，配置后将无法使用", p.ProviderType)
			continue
		}
		def, _ := oauth2.Get(p.ProviderType)
		if got.AuthorizeURL != def.AuthorizeURL || got.TokenURL != def.TokenURL || got.UserInfoURL != def.UserInfoURL {
			t.Errorf("%q 的端点与注册表不一致", p.ProviderType)
		}
		if got.OpenIDURL != def.OpenIDURL {
			t.Errorf("%q 的 openid 端点与注册表不一致", p.ProviderType)
		}
	}
	if _, ok := builtinEndpoints("no-such-type"); ok {
		t.Error("未知类型不应返回内置端点")
	}
}

// TestDefaultProvidersConsistency 内置提供商的 ID/Type 必须唯一，
// 且 ProviderType 必须在 oauth2 注册表中存在，否则配置后无法使用。
func TestDefaultProvidersConsistency(t *testing.T) {
	ids := map[string]bool{}
	types := map[string]bool{}
	for _, p := range defaultProviders {
		if ids[p.ID] {
			t.Errorf("提供商 ID 重复: %q", p.ID)
		}
		ids[p.ID] = true
		if types[p.ProviderType] {
			t.Errorf("ProviderType 重复: %q", p.ProviderType)
		}
		types[p.ProviderType] = true
		if p.DisplayName == "" {
			t.Errorf("提供商 %q 缺少 DisplayName", p.ID)
		}
	}
}
