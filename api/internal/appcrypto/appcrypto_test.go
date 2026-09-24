package appcrypto

import (
	"path/filepath"
	"testing"
)

func TestInitUnreadableKeyFileReturnsError(t *testing.T) {
	// 使用无效的 keyFile 路径，readOrCreateKeyFile 应返回错误而不是回退硬编码密钥
	err := Init("", "/proc/nonexistent/enc.key")
	if err == nil {
		t.Fatal("Init should return error when key file cannot be created")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	if err := Init("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", ""); err != nil {
		t.Fatalf("Init: %v", err)
	}
	plain := "s3cr3t-client-secret"
	enc := Encrypt(plain)
	if enc == plain {
		t.Fatal("Encrypt returned plaintext")
	}
	if got := Decrypt(enc); got != plain {
		t.Fatalf("Decrypt = %q; want %q", got, plain)
	}
}

func TestEncryptEmptyAndAutoKey(t *testing.T) {
	if err := Init("", filepath.Join(t.TempDir(), "enc.key")); err != nil { // no ENCRYPTION_KEY -> auto-generate & persist
		t.Fatalf("Init: %v", err)
	}
	if Encrypt("") != "" {
		t.Fatal("Encrypt empty should be empty")
	}
	// 未配置 ENCRYPTION_KEY 时也应加密落库（不再明文透传）
	if Encrypt("plain") == "plain" {
		t.Fatal("Encrypt without key should encrypt with key")
	}
	if got := Decrypt(Encrypt("plain")); got != "plain" {
		t.Fatalf("Decrypt roundtrip = %q; want %q", got, "plain")
	}
	// 无前缀的遗留明文值仍按原样返回（兼容迁移）
	if Decrypt("plain") != "plain" {
		t.Fatal("Decrypt legacy plaintext should passthrough")
	}
}

func TestInitInvalidKey(t *testing.T) {
	if err := Init("too-short", ""); err == nil {
		t.Fatal("Init should reject short key")
	}
	if err := Init("not-hex-or-base64!!", ""); err == nil {
		t.Fatal("Init should reject invalid encoding")
	}
}
