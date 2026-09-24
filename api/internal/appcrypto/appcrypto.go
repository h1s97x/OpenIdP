// Package secret provides application-level encryption for sensitive values
// stored in the database (OAuth client secrets, SMTP passwords, captcha keys
// and TOTP secrets). It uses AES-256-GCM with a random nonce per value.
//
// Key management:
//   - ENCRYPTION_KEY (32 bytes, hex or base64) enables encryption at rest.
//   - When no key is configured, a random 32-byte key is auto-generated and
//     persisted to DATA_DIR/encryption.key for future restarts. If the key file
//     cannot be read or created, Init returns an error.
//
// Format of an encrypted value: "enc:v1:" + base64(nonce || ciphertext).
// Legacy plaintext rows (no prefix) are returned unchanged by Decrypt, which
// makes adoption a transparent, incremental migration.
package appcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const prefix = "enc:v1:"

var key []byte

// logWarn 输出一次密钥/解密相关的告警（默认打到标准日志）。
var logWarn = func(format string, args ...any) { log.Printf(format, args...) }

// InitAuto 配置应用层加密密钥（AES-256-GCM）：
//   - 优先使用显式传入的 encoded 密钥（hex / base64，32 字节）。
//   - 未配置时，若 keyFile 已存在则读取其中的持久化密钥（重启复用，避免已加密数据无法解密）。
//   - 首次运行且 keyFile 不存在时，自动生成 32 字节强随机密钥并写入 keyFile。
//
// 这样所有敏感字段（OAuth ClientSecret / SMTP 密码 / 验证码密钥 / TOTP 密钥）始终加密落库，
// 且无需任何外部配置即可开箱使用。
func Init(encoded, keyFile string) error {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		k, err := readOrCreateKeyFile(keyFile)
		if err != nil {
			return fmt.Errorf("unable to read or create encryption key file %s: %w", keyFile, err)
		}
		key = k
		return nil
	}
	var k []byte
	if b, err := hex.DecodeString(encoded); err == nil {
		k = b
	} else if b, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		k = b
	} else {
		return errors.New("ENCRYPTION_KEY must be a 32-byte key (hex or base64 encoded)")
	}
	if len(k) != 32 {
		return errors.New("ENCRYPTION_KEY must be exactly 32 bytes (AES-256)")
	}
	key = k
	return nil
}

// readOrCreateKeyFile 读取已有的持久化密钥文件，或生成一个新的 32 字节随机密钥并写入。
// 文件内容为单个 32 字节密钥的 hex 编码（单行），便于人工备份与迁移。
func readOrCreateKeyFile(keyFile string) ([]byte, error) {
	if b, err := os.ReadFile(keyFile); err == nil {
		data := strings.TrimSpace(string(b))
		if h, hErr := hex.DecodeString(data); hErr == nil && len(h) == 32 {
			return h, nil
		}
	}
	// 生成新密钥并持久化
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return raw, nil
}

// Enabled reports whether encryption-at-rest is active.
func Enabled() bool { return key != nil }

// Encrypt encrypts plaintext. Empty plaintext and the no-key case are returned
// unchanged so callers can safely pass them through.
func Encrypt(plain string) string {
	if plain == "" || key == nil {
		return plain
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return plain
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plain
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return plain
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return prefix + base64.RawURLEncoding.EncodeToString(sealed)
}

// Decrypt decrypts a value produced by Encrypt.
//
// 兼容性说明（何时可移除）：加密是增量落库的，早期数据可能是明文（无 "enc:v1:" 前缀），
// 这类值原样返回，保证升级过程中不中断。当所有存量数据都完成加密回填后，
// 可以去掉这个分支（即不再接受明文值）。
//
// 另：解密失败（密钥不匹配/数据损坏）时返回密文原文——调用方随后会校验失败并报错，
// 而不是让 TOTP / OAuth 静默通过校验。
func Decrypt(v string) string {
	if !strings.HasPrefix(v, prefix) {
		return v
	}
	if key == nil {
		// 没有密钥无法解密：返回存储值，让调用方校验失败并显式报错，
		// 而不是把密文当成可用凭据静默放行。
		logWarn("⚠️ [Secret] 未配置加密密钥，无法解密密文字段（请检查 ENCRYPTION_KEY 或 DATA_DIR/encryption.key）")
		return v
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v, prefix))
	if err != nil {
		logWarn("⚠️ [Secret] 密文 base64 解码失败（%v）——请检查 ENCRYPTION_KEY / DATA_DIR/encryption.key 是否被更换", err)
		return v
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		logWarn("❌ [Secret] 初始化 AES 失败（%v）", err)
		return v
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		logWarn("❌ [Secret] 初始化 GCM 失败（%v）", err)
		return v
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		logWarn("⚠️ [Secret] 密文长度非法（太短）——数据损坏或密钥不匹配")
		return v
	}
	nonce, ciphertext := raw[:ns], raw[ns:]
	out, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// 解密失败最常见原因是 ENCRYPTION_KEY / encryption.key 已更换：记 WARNING
		// 暴露密钥管理事故，而不是让 TOTP / OAuth / SMTP 以密文当凭据静默失败。
		logWarn("❌ [Secret] 解密失败（%v）——数据损坏或加密密钥已变更（请检查 ENCRYPTION_KEY / DATA_DIR/encryption.key）", err)
		return v
	}
	return string(out)
}
