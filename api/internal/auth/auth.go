package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"runtime"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// passwordSem 限制同时进行的 bcrypt 计算的并发数。
//
// bcrypt cost 12 每次约 40ms 纯 CPU 开销，实测 8 核机器吞吐仅 ~24 rps；
// 并发登录不加限制会直接把所有核心占满，拖慢同进程的其它端点（健康检查、
// 静态资源、正常业务请求）直到超时。这里把并发压到 CPU 核数量级：
// 既能让单次登录仍以满核速度完成，又保证进程整体不会被密码校验打满。
var passwordSem = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)))

// acquirePasswordSlot 获取一个 bcrypt 计算名额（满则等待）。
func acquirePasswordSlot() { passwordSem <- struct{}{} }

// releasePasswordSlot 归还名额。
func releasePasswordSlot() { <-passwordSem }

// SessionIDHash 返回会话 ID 的 SHA-256 摘要（十六进制）。
//
// 会话表只保存摘要，Cookie 里放原始值：数据库或备份泄露不再等价于会话劫持。
//
// 实现统一收敛在这里：handler 层（登录/校验/删除会话）与 db 层（存量数据回填
// session_hash）都要用同一算法。此前两处各写了一份，一旦其中一处改动漂移，
// 回填出的摘要就会与实际登录时算出的对不上，导致老会话全部失效。
func SessionIDHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// HashPassword bcrypt-hashes a plaintext password (cost 12).
// 通过全局并发闸门限制同时进行的哈希计算数（见 passwordSem）。
func HashPassword(pw string) (string, error) {
	acquirePasswordSlot()
	defer releasePasswordSlot()
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword verifies a password against a bcrypt hash.
// 同样受并发闸门约束：登录是攻击者最容易触发的 bcrypt 调用路径。
func CheckPassword(hash, pw string) bool {
	acquirePasswordSlot()
	defer releasePasswordSlot()
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// RandomToken returns a URL-safe random token of n bytes.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// RandomHex returns a hex string of n random bytes (used for request IDs).
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewSubject generates a stable user subject: usr_<hex>.
func NewSubject() string {
	return "usr_" + RandomHex(16)
}

// NewID generates a UUID-like identifier for sessions/devices.
func NewID() string {
	return RandomToken(24)
}

// FirstNonEmpty returns the first non-blank value among vals.
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
