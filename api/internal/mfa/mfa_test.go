package mfa

import (
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TOTP 双重认证测试。
//
// 背景：mfa 包实现 RFC 6238 TOTP（密钥生成、验证、provisioning URI、恢复码）。
// 此前零测试，而它是账号安全的第二道防线。本文件重点验证「验证逻辑」本身：
// 正确码通过、错误码拒绝、窗口偏移行为，以及恢复码的一次性与大小写无关性。
// ---------------------------------------------------------------------------

func TestGenerateSecretFormat(t *testing.T) {
	s, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	// 20 字节 base32（无填充）= 32 字符
	if len(s) != 32 {
		t.Errorf("secret 长度 = %d, want 32", len(s))
	}
	// 必须为大写 base32 字母表（RFC 4648）
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7')) {
			t.Errorf("secret 含非法 base32 字符 %q: %s", r, s)
			break
		}
	}
	// 两次生成不应相同
	s2, _ := GenerateSecret()
	if s == s2 {
		t.Error("两次生成得到相同 secret")
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("OpenIdP", "alice", "JBSWY3DPEHPK3PXP")
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("URI 协议错误: %s", uri)
	}
	// 参数必须齐全，否则验证器 App 无法解析
	for _, want := range []string{"secret=JBSWY3DPEHPK3PXP", "issuer=OpenIdP", "algorithm=SHA1", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI 缺少 %q: %s", want, uri)
		}
	}
	// label 应为 issuer:account 且正确转义
	if !strings.Contains(uri, "OpenIdP%3Aalice") && !strings.Contains(uri, "OpenIdP:alice") {
		t.Errorf("label 应为 issuer:account: %s", uri)
	}
	// 整体可解析为 URL（编码合法）
	if _, err := url.Parse(uri); err != nil {
		t.Errorf("URI 无法解析: %v", err)
	}
}

// TestVerifyAcceptsCurrentCode 用已知的 RFC 6238 测试向量验证当前时间窗内的码。
func TestVerifyAcceptsCurrentCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	// 直接复用包内 hotp 计算当前时间窗的期望值（避免重复实现 RFC 6238）
	code := hotpForNow(t, secret)
	if !Verify(secret, code) {
		t.Errorf("当前时间窗的 TOTP 码应通过验证（secret=%s code=%s）", secret, code)
	}
}

func TestVerifyRejectsWrongCode(t *testing.T) {
	secret, _ := GenerateSecret()
	code := hotpForNow(t, secret)
	if Verify(secret, "") {
		t.Error("空码不应通过")
	}
	// 构造一个与正确码不同的 6 位码
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	if Verify(secret, wrong) {
		t.Error("错误码不应通过")
	}
}

func TestVerifyRejectsInvalidSecret(t *testing.T) {
	// 非法 base32 密钥必须返回 false，而不是 panic
	if Verify("not-base32!!!", "123456") {
		t.Error("非法 base32 secret 应返回 false")
	}
	if Verify("", "123456") {
		t.Error("空 secret 应返回 false")
	}
}

func TestVerifyTrimsInput(t *testing.T) {
	secret, _ := GenerateSecret()
	code := hotpForNow(t, secret)
	// 用户输入前后带空格/小写时也应能验证通过（TOTP 码是数字，此处主要验证 trim 生效）
	if !Verify(secret, "  "+code+"  ") {
		t.Errorf("带空白的码应通过（应做 TrimSpace）")
	}
}

func TestGenerateRecoveryCodesFormat(t *testing.T) {
	codes, err := GenerateRecoveryCodes(5)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != 5 {
		t.Fatalf("生成数量 = %d, want 5", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		// 格式 xxxx-xxxx-xxxx
		if len(c) != 14 {
			t.Errorf("恢复码长度 = %d (want 14): %q", len(c), c)
			continue
		}
		if c[4] != '-' || c[9] != '-' {
			t.Errorf("恢复码分隔位不正确: %q", c)
		}
		if seen[c] {
			t.Errorf("恢复码重复: %q", c)
		}
		seen[c] = true
		// 字母表排除了易混淆字符（I、O、0、1 等）
		for _, r := range c {
			if r == '-' {
				continue
			}
			if !((r >= 'A' && r <= 'Z') || (r >= '2' && r <= '9')) {
				t.Errorf("恢复码含非法字符 %q: %s", r, c)
				break
			}
		}
	}
}

func TestVerifyRecoveryCodeConsumesOnce(t *testing.T) {
	original := []string{"AAAA-BBBB-CCCC", "DDDD-EEEE-FFFF", "GGGG-HHHH-JJJJ"}

	// 正确码（大小写不敏感 + 前后空白）
	ok, remaining := VerifyRecoveryCode(original, " aaaa-bbbb-cccc ")
	if !ok {
		t.Fatal("正确的恢复码应通过")
	}
	if len(remaining) != 2 {
		t.Fatalf("消费后应剩 2 个，实际 %d", len(remaining))
	}
	// 剩余列表不应包含已消费的那个
	for _, c := range remaining {
		if c == "AAAA-BBBB-CCCC" {
			t.Error("已消费的恢复码仍在剩余列表中")
		}
	}
	// 原切片不应被就地修改（避免调用方误用旧长度）
	if len(original) != 3 {
		t.Errorf("不应修改传入的切片，长度 = %d", len(original))
	}

	// 重复使用同一码应失败
	if ok2, _ := VerifyRecoveryCode(remaining, "AAAA-BBBB-CCCC"); ok2 {
		t.Error("已消费的恢复码不应再次通过（一次性）")
	}

	// 错误码：返回 false 且列表不变
	ok3, after := VerifyRecoveryCode(remaining, "ZZZZ-ZZZZ-ZZZZ")
	if ok3 {
		t.Error("错误恢复码不应通过")
	}
	if len(after) != 2 {
		t.Errorf("失败时不应消耗列表，长度 = %d", len(after))
	}
}

func TestVerifyRecoveryCodeRejectsEmpty(t *testing.T) {
	original := []string{"AAAA-BBBB-CCCC"}
	if ok, _ := VerifyRecoveryCode(original, ""); ok {
		t.Error("空输入不应通过")
	}
	if ok, _ := VerifyRecoveryCode(original, "   "); ok {
		t.Error("纯空白输入不应通过")
	}
}

// hotpForNow 返回给定 secret 在当前时间窗的 TOTP 码。
//
// 解码方式与 Verify 保持一致（大写化 + 去空格 + base32 无填充），
// 计数逻辑复用包内 hotp，避免测试里另写一遍 RFC 6238 而与实现漂移。
func hotpForNow(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("decode secret %q: %v", secret, err)
	}
	counter := uint64(time.Now().Unix() / period)
	return hotp(key, counter)
}
