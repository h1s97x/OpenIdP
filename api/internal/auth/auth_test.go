package auth

import (
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 密码哈希与随机 token：覆盖安全相关核心函数。
//
// 背景：auth 包是登录、改密、重置等所有身份操作的底层（bcrypt、随机数）。
// 此前零测试，bcrypt 行为或 token 格式若退化，线上不会被任何单测拦截。
// ---------------------------------------------------------------------------

// TestHashPasswordIsBCrypt 检查哈希产出 bcrypt 标准格式：
// 前缀 $2a$/$2b$/$2y$，cost=12（前两位数字），盐长 22（53 字符 base64）。
func TestHashPasswordIsBCrypt(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// 接受任意 bcrypt 2x variant
	if !regexp.MustCompile(`^\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}$`).MatchString(hash) {
		t.Errorf("hash 不符合 bcrypt 格式: %q", hash)
	}
	// 我们的 cost 必须是 12（README 中也有说明）；这是安全与性能的折中
	if !strings.HasPrefix(hash, "$2") || !strings.Contains(hash[:5], "12$") {
		// 简单断言：cost 字段位于 $2x$ 与盐之间
		parts := strings.Split(hash, "$")
		if len(parts) < 4 || parts[2] != "12" {
			t.Errorf("expected cost=12, got cost=%q in hash %q", parts[2], hash)
		}
	}
}

func TestCheckPasswordAcceptsCorrectAndRejectsWrong(t *testing.T) {
	hash, err := HashPassword("MyP@ssw0rd!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !CheckPassword(hash, "MyP@ssw0rd!") {
		t.Error("正确的密码应通过校验")
	}
	if CheckPassword(hash, "wrong") {
		t.Error("错误密码不应通过")
	}
	if CheckPassword(hash, "") {
		t.Error("空字符串不应通过（不是合法输入）")
	}
}

func TestCheckPasswordRejectsTamperedHash(t *testing.T) {
	// 即使密码正确，篡改后的哈希也必须失败——防止"将空哈希/默认哈希植入"
	if CheckPassword("$2a$12$"+strings.Repeat("A", 53), "correct") {
		t.Error("被篡改的哈希不应通过校验")
	}
	// 完全非 bcrypt 格式也应直接 false（不可 panic）
	if CheckPassword("not-a-bcrypt-hash", "correct") {
		t.Error("非法格式哈希应返回 false")
	}
}

func TestRandomTokenFormat(t *testing.T) {
	tok := RandomToken(32)
	// base64.RawURLEncoding 长度 = ceil(32*4/3) = 43
	if want := 43; len(tok) != want {
		t.Errorf("RandomToken(32) 长度 = %d, want %d", len(tok), want)
	}
	// 不应含 URL-unsafe 字符
	if strings.ContainsAny(tok, "+/=") {
		t.Errorf("URL-safe 编码却含标准 base64 字符: %q", tok)
	}
	// 多次生成应得到不同结果（无种子问题）
	a, b := RandomToken(32), RandomToken(32)
	if a == b {
		t.Errorf("两次生成得到相同 token: %q", a)
	}
}

func TestRandomHexFormat(t *testing.T) {
	hex := RandomHex(8)
	if len(hex) != 16 {
		t.Errorf("RandomHex(8) 长度 = %d, want 16", len(hex))
	}
	if matched, _ := regexp.MatchString(`^[0-9a-f]+$`, hex); !matched {
		t.Errorf("非全小写十六进制: %q", hex)
	}
}

func TestNewSubjectFormat(t *testing.T) {
	s := NewSubject()
	if !strings.HasPrefix(s, "usr_") {
		t.Errorf("subject 应以 usr_ 开头: %q", s)
	}
	if len(s) != 4+32 { // "usr_" + 32 字符 hex
		t.Errorf("subject 长度 = %d, want 36", len(s))
	}
}

func TestNewIDFormat(t *testing.T) {
	id := NewID()
	if len(id) != 32 { // 24 字节 base64.RawURLEncoding = 32 字符
		t.Errorf("NewID 长度 = %d, want 32", len(id))
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := FirstNonEmpty("", "  ", "x", "y"); got != "x" {
		t.Errorf("FirstNonEmpty(空,空格,x,y) = %q, want x", got)
	}
	if got := FirstNonEmpty("", "  ", "\t"); got != "" {
		t.Errorf("全部空白应返回空: %q", got)
	}
	if got := FirstNonEmpty("only", ""); got != "only" {
		t.Errorf("FirstNonEmpty(only,) = %q, want only", got)
	}
}
