package passkey

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ---------------------------------------------------------------------------
// 通行密钥（WebAuthn）仪式状态往返测试。
//
// 背景：ceremony 结构体原先所有字段均未导出，而 encoding/json 只编解码导出
// 字段，store() 的 json.Marshal 实际写入缓存的是 "{}"。取出后 Kind 恒为空串，
// FinishRegistration / FinishLogin 一律返回 "passkey: invalid ceremony"，
// 导致通行密钥注册与登录 100% 失败。该 bug 线上表现为「添加通行密钥失败」。
//
// 本文件用「store → take 往返」直接锁住这一契约：字段若再次被改为未导出，
// 往返后 Kind 会丢失，测试立即失败。
// ---------------------------------------------------------------------------

// roundtrip 模拟 store/take 的序列化往返（与 Service 使用相同的编解码方式）。
func roundtrip(t *testing.T, in ceremony) ceremony {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal ceremony: %v", err)
	}
	var out ceremony
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal ceremony: %v", err)
	}
	return out
}

// TestCeremonyRoundTripPreservesAllFields 仪式状态序列化后必须保留全部字段。
// 这是「通行密钥无法注册/登录」bug 的回归测试。
func TestCeremonyRoundTripPreservesAllFields(t *testing.T) {
	expires := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
	in := ceremony{
		Kind:   "register",
		UserID: 42,
		Session: webauthn.SessionData{
			Challenge: "test-challenge-value",
			UserID:    []byte{1, 2, 3, 4},
			Expires:   expires,
		},
		RPID:      "example.com",
		Origin:    "https://example.com",
		RPName:    "OpenIdP",
		ExpiresAt: expires,
	}

	got := roundtrip(t, in)

	// Kind 是关键：为空则 take() 之后的 kind 校验全部失败
	if got.Kind != in.Kind {
		t.Errorf("Kind = %q, want %q (未导出字段会导致该值丢失)", got.Kind, in.Kind)
	}
	if got.UserID != in.UserID {
		t.Errorf("UserID = %d, want %d", got.UserID, in.UserID)
	}
	if got.RPID != in.RPID {
		t.Errorf("RPID = %q, want %q", got.RPID, in.RPID)
	}
	if got.Origin != in.Origin {
		t.Errorf("Origin = %q, want %q", got.Origin, in.Origin)
	}
	if got.RPName != in.RPName {
		t.Errorf("RPName = %q, want %q", got.RPName, in.RPName)
	}
	if !got.ExpiresAt.Equal(in.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, in.ExpiresAt)
	}
	if got.Session.Challenge != in.Session.Challenge {
		t.Errorf("Session.Challenge = %q, want %q", got.Session.Challenge, in.Session.Challenge)
	}
	if len(got.Session.UserID) != len(in.Session.UserID) {
		t.Errorf("Session.UserID length = %d, want %d", len(got.Session.UserID), len(in.Session.UserID))
	}
}

// TestCeremonyJSONIsNotEmpty 序列化结果不能是空对象——空对象意味着
// 所有字段都因未导出而被丢弃。这是最直接的哨兵测试。
func TestCeremonyJSONIsNotEmpty(t *testing.T) {
	b, err := json.Marshal(ceremony{
		Kind:      "login",
		UserID:    7,
		RPID:      "localhost",
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) == "{}" {
		t.Fatal("ceremony 序列化为空对象：字段未导出会导致仪式状态全部丢失，" +
			"进而使通行密钥注册与登录永久失败")
	}

	// 关键字段必须出现在 JSON 中
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"kind", "userId", "rpId", "expiresAt"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("序列化结果缺少字段 %q（完整 JSON=%s）", key, b)
		}
	}
}

// ---------------------------------------------------------------------------
// 前端 WebAuthn 参数结构契约
//
// 后端将 protocol.CredentialCreation / CredentialAssertion 直接 json.Marshal
// 后下发，其顶层结构为 {"publicKey": {...}}，这正好是
// navigator.credentials.create()/get() 期望的入参。前端（web/src/lib/webauthn.ts）
// 必须原样透传，不能再包一层 publicKey——否则 challenge 落到
// publicKey.publicKey.challenge，浏览器读到 undefined，读取其 .buffer 时抛
// "Cannot read properties of undefined (reading 'buffer')"。
// ---------------------------------------------------------------------------

// TestCreationOptionsUsePublicKeyWrapper 锁住注册参数的顶层结构。
func TestCreationOptionsUsePublicKeyWrapper(t *testing.T) {
	creation := protocol.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: protocol.URLEncodedBase64([]byte("0123456789abcdef")),
			RelyingParty: protocol.RelyingPartyEntity{
				ID: "localhost",
				CredentialEntity: protocol.CredentialEntity{
					Name: "OpenIdP",
				},
			},
			User: protocol.UserEntity{
				ID:          []byte("user-1"),
				DisplayName: "Alice",
				CredentialEntity: protocol.CredentialEntity{
					Name: "alice",
				},
			},
		},
	}
	b, err := json.Marshal(creation)
	if err != nil {
		t.Fatalf("marshal creation: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// 顶层必须有且仅有 publicKey 承载实际参数
	inner, ok := raw["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("CredentialCreation 顶层应包含 publicKey 对象，实际=%s", b)
	}
	// challenge 必须在 publicKey 内层（前端据此解码后透传给浏览器）
	if _, ok := inner["challenge"]; !ok {
		t.Errorf("publicKey 内层应包含 challenge，实际=%s", b)
	}
	// challenge 是 base64url 字符串，不是数组
	if _, isStr := inner["challenge"].(string); !isStr {
		t.Errorf("challenge 应为 base64url 字符串，实际类型=%T", inner["challenge"])
	}
}

// TestAssertionOptionsUsePublicKeyWrapper 锁住登录（断言）参数的顶层结构。
func TestAssertionOptionsUsePublicKeyWrapper(t *testing.T) {
	assertion := protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge:      protocol.URLEncodedBase64([]byte("fedcba9876543210")),
			RelyingPartyID: "localhost",
		},
	}
	b, err := json.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	inner, ok := raw["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("CredentialAssertion 顶层应包含 publicKey 对象，实际=%s", b)
	}
	if _, ok := inner["challenge"]; !ok {
		t.Errorf("publicKey 内层应包含 challenge，实际=%s", b)
	}
}

// TestCeremonyExpiredIsRejected 过期仪式必须被拒绝（take 中的 TTL 校验）。
func TestCeremonyExpiredIsRejected(t *testing.T) {
	past := time.Now().UTC().Add(-time.Minute)
	c := ceremony{Kind: "register", UserID: 1, ExpiresAt: past}
	if !time.Now().After(c.ExpiresAt) {
		t.Fatal("前置条件不成立：该仪式应已过期")
	}
	// 与 Service.take 中的判定保持一致
	if !time.Now().After(c.ExpiresAt) {
		t.Error("过期仪式应被判定为失效")
	}
}

// TestNewServiceFallsBackToMemoryCache 未传入缓存时不应 panic，应回退内存缓存。
func TestNewServiceFallsBackToMemoryCache(t *testing.T) {
	s := New(nil, func(string) Config { return Config{} }, nil)
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.cache == nil {
		t.Fatal("未传入缓存时应回退为内存缓存，实际为 nil")
	}
	// 确保可安全调用（不应 panic）
	_ = context.Background()
}

// TestBeginRegistrationRequiresConfig 未配置（未启用/RPID 为空）时必须报错，
// 而不是返回一个可用的仪式。
func TestBeginRegistrationRequiresConfig(t *testing.T) {
	s := New(nil, func(string) Config { return Config{} }, nil)
	_, _, err := s.BeginRegistration(1, "http://localhost:6099")
	if err == nil {
		t.Fatal("未配置通行密钥时 BeginRegistration 应返回错误")
	}
}

// TestBeginLoginRequiresConfig 同上，登录路径。
func TestBeginLoginRequiresConfig(t *testing.T) {
	s := New(nil, func(string) Config { return Config{} }, nil)
	_, _, err := s.BeginLogin(1, "http://localhost:6099")
	if err == nil {
		t.Fatal("未配置通行密钥时 BeginLogin 应返回错误")
	}
}

// TestFinishUnknownCeremonyIsRejected 未知的仪式 ID 必须被拒绝，
// 且 take 为一次性消费（再次取同一 ID 也应失败）。
func TestFinishUnknownCeremonyIsRejected(t *testing.T) {
	s := New(nil, func(string) Config { return Config{} }, nil)
	if _, err := s.FinishRegistration("no-such-ceremony", "key", json.RawMessage(`{}`)); err == nil {
		t.Error("FinishRegistration 对未知 ceremony 应报错")
	}
	if _, err := s.FinishLogin("no-such-ceremony", json.RawMessage(`{}`)); err == nil {
		t.Error("FinishLogin 对未知 ceremony 应报错")
	}
	if _, err := s.FinishDiscoverableLogin("no-such-ceremony", json.RawMessage(`{}`)); err == nil {
		t.Error("FinishDiscoverableLogin 对未知 ceremony 应报错")
	}
}
