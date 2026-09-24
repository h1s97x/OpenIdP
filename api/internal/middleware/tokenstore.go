package middleware

import (
	"context"
	"encoding/json"
	"time"

	"github.com/h1s97x/openidp/api/internal/cache"
)

// TokenItem is a stored token bound to a session (optional).
type TokenItem struct {
	UserID  int64     `json:"userID"`
	Session string    `json:"session,omitempty"`
	Expires time.Time `json:"expires"`
}

// TokenStore is a concurrency-safe token store with TTL, backed by a shared
// cache (Redis when available, in-memory otherwise). It backs CSRF tokens as
// well as one-time proof / OAuth state tokens.
type TokenStore struct {
	cache cache.Cache
	ttl   time.Duration
}

// NewTokenStore creates a token store. ttl is the lifetime of each token;
// expired entries are purged by the underlying cache.
func NewTokenStore(c cache.Cache, ttl time.Duration) *TokenStore {
	return &TokenStore{cache: c, ttl: ttl}
}

func tokenKey(token string) string { return "tok:" + token }

// Set stores a token. A non-empty session binds the token to that session.
// 使用 Store 的默认 TTL（CSRF 令牌等按此口径）。
func (ts *TokenStore) Set(token string, userID int64, session string) {
	ts.SetWithTTL(token, userID, session, ts.ttl)
}

// SetWithTTL 以指定 TTL 存储令牌，用于有效期与默认值不同的短效凭据。
//
// step-up / reauth 令牌就是这类：接口向用户承诺的有效期是 600 秒，
// 若统一按 Store 的默认 TTL（30 分钟）落库，校验时又只看令牌自身的 Expires，
// 用户看到的窗口与实际生效的窗口就会相差 3 倍——重验证的实际保护被显著放宽。
func (ts *TokenStore) SetWithTTL(token string, userID int64, session string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = ts.ttl
	}
	it := TokenItem{UserID: userID, Session: session, Expires: time.Now().Add(ttl)}
	b, _ := json.Marshal(it)
	ts.cache.Set(context.Background(), tokenKey(token), string(b), ttl)
}

// TTL 返回 Store 的默认令牌有效期。
func (ts *TokenStore) TTL() time.Duration { return ts.ttl }

func (ts *TokenStore) get(token string) (TokenItem, bool) {
	raw, ok := ts.cache.Get(context.Background(), tokenKey(token))
	if !ok {
		return TokenItem{}, false
	}
	var it TokenItem
	if err := json.Unmarshal([]byte(raw), &it); err != nil {
		return TokenItem{}, false
	}
	return it, true
}

// Check verifies a token exists, is unexpired, and — when the token is bound
// to a session — that the caller carries the matching session cookie.
// Tokens stored without a session binding (one-time proofs, OAuth state)
// are only checked for existence/expiry.
func (ts *TokenStore) Check(token, session string) bool {
	it, ok := ts.get(token)
	if !ok {
		return false
	}
	if time.Now().After(it.Expires) {
		return false
	}
	if it.Session != "" {
		// Bound CSRF token: the caller must present the exact session.
		return it.Session == session
	}
	return true
}

// Has reports whether a token exists and is unexpired (no session check).
func (ts *TokenStore) Has(token string) bool {
	it, ok := ts.get(token)
	if !ok {
		return false
	}
	return time.Now().Before(it.Expires)
}

// Take atomically retrieves and removes a one-time token.
// 用 GetDel 语义消费（Redis 单命令原子、内存实现加锁），避免“先读后删”
// 在并发下把同一个一次性 token 消费多次（重放）。
func (ts *TokenStore) Take(token string) (TokenItem, bool) {
	raw, ok := ts.cache.GetDel(context.Background(), tokenKey(token))
	if !ok {
		return TokenItem{}, false
	}
	var it TokenItem
	if err := json.Unmarshal([]byte(raw), &it); err != nil {
		return TokenItem{}, false
	}
	if time.Now().After(it.Expires) {
		return TokenItem{}, false
	}
	return it, true
}

// Delete removes a token if present.
func (ts *TokenStore) Delete(token string) {
	ts.cache.Del(context.Background(), tokenKey(token))
}

// csrfIndexPrefix 是「会话 -> 当前 CSRF 令牌」索引的键前缀。
const csrfIndexPrefix = "csrf:sess:"

// SessionCSRFToken 返回该会话当前绑定的、仍未过期的 CSRF 令牌（无则空串）。
// 用于复用会话令牌，避免每次刷新会话都增发新令牌导致令牌无限堆积。
func (ts *TokenStore) SessionCSRFToken(session string) string {
	if session == "" {
		return ""
	}
	it, ok := ts.get(csrfIndexPrefix + session)
	if !ok || it.Session == "" {
		return ""
	}
	// 索引里 Session 字段存的是令牌明文；再确认该令牌仍有效且绑定到同一会话。
	cur, ok := ts.get(it.Session)
	if !ok || cur.Session != session {
		return ""
	}
	return it.Session
}

// BindSessionCSRFToken 记录会话当前使用的 CSRF 令牌（TTL 与令牌一致）。
func (ts *TokenStore) BindSessionCSRFToken(session, token string, userID int64) {
	if session == "" || token == "" {
		return
	}
	ts.Set(csrfIndexPrefix+session, userID, token)
}

// UserOf 返回绑定在该 token 上的用户 ID（不存在时返回 0）。
// 用于「令牌有效但需确认归属」的场景（如 step-up 令牌必须属于当前用户）。
func (ts *TokenStore) UserOf(token string) int64 {
	it, ok := ts.get(token)
	if !ok || time.Now().After(it.Expires) {
		return 0
	}
	return it.UserID
}
