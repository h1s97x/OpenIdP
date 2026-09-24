package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ---------------------------------------------------------------------------
// OIDC 密钥与 ID Token 签发测试。
//
// 背景：oidc 包此前零测试，而它承载 RSA 签名密钥的持久化与 ID Token 签发——
// 密钥若每次重启都重新生成，所有已签发的 token 会全部失效（历史上曾因此
// 把 JWT 密钥改为持久化到 DATA_DIR）。本文件锁定这一行为。
// ---------------------------------------------------------------------------

// TestNewProviderEphemeral 不传目录时应可用（临时密钥），用于测试/开发环境。
func TestNewProviderEphemeral(t *testing.T) {
	p, err := NewProvider("")
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p == nil {
		t.Fatal("NewProvider returned nil")
	}
	keys := p.JWKS().Keys
	if len(keys) != 1 {
		t.Fatalf("JWKS 应含 1 个公钥，实际 %d", len(keys))
	}
	// 公钥算法与用途必须正确声明，否则客户端无法校验签名
	if keys[0].Algorithm != string(jose.RS256) {
		t.Errorf("alg = %q, want RS256", keys[0].Algorithm)
	}
	if keys[0].Use != "sig" {
		t.Errorf("use = %q, want sig", keys[0].Use)
	}
	if keys[0].KeyID == "" {
		t.Error("kid 不应为空（客户端需据此匹配密钥）")
	}
	// JWKS 中只能暴露公钥，绝不能包含私钥
	if _, ok := keys[0].Key.(*rsa.PublicKey); !ok {
		t.Errorf("JWKS 中的密钥类型 = %T, want *rsa.PublicKey", keys[0].Key)
	}
	if keys[0].IsPublic() == false {
		t.Error("JWKS 暴露的应为公钥")
	}
}

// TestKeyPersistsAcrossRestarts 密钥必须持久化：
// 重启（重新 NewProvider）后应使用同一把密钥，否则已签发的 token 全部失效。
func TestKeyPersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	p1, err := NewProvider(dir)
	if err != nil {
		t.Fatalf("first NewProvider: %v", err)
	}
	// 签发一个 token，随后"重启"再用新 Provider 校验
	token, err := p1.SignIDToken("https://issuer", "usr_1", "client-1", "", nil, time.Hour)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}

	p2, err := NewProvider(dir) // 模拟重启
	if err != nil {
		t.Fatalf("second NewProvider: %v", err)
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	var claims jwt.Claims
	// 用 p2 的公钥校验 p1 签发的 token：能过说明密钥未变
	if err := parsed.Claims(p2.JWKS().Keys[0].Key, &claims); err != nil {
		t.Fatalf("重启后无法校验此前签发的 token（密钥发生了变化）: %v", err)
	}
	if claims.Subject != "usr_1" {
		t.Errorf("sub = %q, want usr_1", claims.Subject)
	}
}

// TestKeyFilePermissions 密钥文件必须仅限属主读写（0o600），否则同机其他用户可读取签名密钥。
func TestKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewProvider(dir); err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	path := filepath.Join(dir, "rsa.pem")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("密钥文件权限 = %o, want 600", perm)
	}
}

// TestLoadOrCreateKeyRejectsCorruptFile 密钥文件损坏时必须报错，
// 而不是静默生成新密钥（后者会让所有已签发 token 悄悄失效，难以排查）。
func TestLoadOrCreateKeyRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rsa.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadOrCreateKey(path); err == nil {
		t.Error("损坏的密钥文件应返回错误")
	}
	// 顺带验证 NewProvider 也会把错误向上传播
	if _, err := NewProvider(dir); err == nil {
		t.Error("NewProvider 应传播密钥加载错误")
	}
}

func TestSignIDTokenClaims(t *testing.T) {
	p, err := NewProvider("")
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	nonce := "nonce-abc"
	token, err := p.SignIDToken(
		"https://issuer.example.com", "usr_9", "client-9", nonce,
		map[string]any{"email": "a@example.com"}, 30*time.Minute,
	)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	if token == "" {
		t.Fatal("token 不应为空")
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var std jwt.Claims
	var extra map[string]any
	key := p.JWKS().Keys[0].Key
	if err := parsed.Claims(key, &std, &extra); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if std.Issuer != "https://issuer.example.com" {
		t.Errorf("iss = %q", std.Issuer)
	}
	if std.Subject != "usr_9" {
		t.Errorf("sub = %q", std.Subject)
	}
	if len(std.Audience) != 1 || std.Audience[0] != "client-9" {
		t.Errorf("aud = %v", std.Audience)
	}
	if extra["nonce"] != nonce {
		t.Errorf("nonce = %v, want %q", extra["nonce"], nonce)
	}
	if extra["email"] != "a@example.com" {
		t.Errorf("email = %v", extra["email"])
	}
	// 过期时间应在未来且不超过 ttl
	if std.Expiry == nil || !std.Expiry.Time().After(time.Now()) {
		t.Errorf("exp 应在未来: %v", std.Expiry)
	}
	if d := time.Until(std.Expiry.Time()); d > 31*time.Minute {
		t.Errorf("exp 超出 ttl: %v", d)
	}
}

// TestSignIDTokenOmitsNonceWhenEmpty 未传 nonce 时不应写入空的 nonce 声明
// （OIDC 中 nonce 缺失与空字符串语义不同，混用会导致客户端校验失败）。
func TestSignIDTokenOmitsNonceWhenEmpty(t *testing.T) {
	p, _ := NewProvider("")
	token, err := p.SignIDToken("iss", "sub", "aud", "", nil, time.Hour)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	parsed, _ := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	var std jwt.Claims
	var extra map[string]any
	if err := parsed.Claims(p.JWKS().Keys[0].Key, &std, &extra); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, ok := extra["nonce"]; ok {
		t.Errorf("未传 nonce 时不应写入该声明，实际 = %v", extra["nonce"])
	}
}

// TestSignIDTokenUsesKIDHeader 签名头必须带 kid，否则客户端在多密钥时无法定位验签密钥。
func TestSignIDTokenUsesKIDHeader(t *testing.T) {
	p, _ := NewProvider("")
	token, err := p.SignIDToken("iss", "sub", "aud", "", nil, time.Hour)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	// 直接解析 JWS 保护层读取 kid（jwt.JSONWebToken 未导出 signatures 字段）
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("ID Token 应为三段式 JWS，实际 %d 段", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if header.Alg != "RS256" {
		t.Errorf("alg = %q, want RS256", header.Alg)
	}
	if header.Kid == "" {
		t.Error("签名头缺少 kid")
	}
	if header.Kid != p.JWKS().Keys[0].KeyID {
		t.Errorf("签名头 kid = %q, JWKS kid = %q（不一致则无法验签）", header.Kid, p.JWKS().Keys[0].KeyID)
	}
}
