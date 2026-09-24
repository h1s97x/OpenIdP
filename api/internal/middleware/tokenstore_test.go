package middleware

import (
	"testing"
	"time"

	"github.com/h1s97x/openidp/api/internal/cache"
)

func newTestCache() cache.Cache {
	c, _ := cache.New(cache.Options{})
	return c
}

func TestTokenStoreBindSession(t *testing.T) {
	ts := NewTokenStore(newTestCache(), time.Minute)
	ts.Set("tokA", 1, "sessA")
	ts.Set("tokB", 1, "sessB")

	// 正确配对
	if !ts.Check("tokA", "sessA") {
		t.Fatal("tokA/sessA should pass")
	}
	if !ts.Check("tokB", "sessB") {
		t.Fatal("tokB/sessB should pass")
	}
	// 跨会话必须失败
	if ts.Check("tokA", "sessB") {
		t.Fatal("tokA with sessB should be rejected")
	}
	if ts.Check("tokB", "sessA") {
		t.Fatal("tokB with sessA should be rejected")
	}
	// 空会话（未绑定 cookie 时）：绑定的 CSRF token 必须携带匹配 cookie
	if ts.Check("tokA", "") {
		t.Fatal("bound token without caller session should be rejected")
	}
	// 未绑定 session 的 token（一次性证明/OAuth state）：仅检查存在
	ts.Set("proof1", 0, "")
	if !ts.Check("proof1", "") {
		t.Fatal("unbound token should pass regardless of caller session")
	}
	if !ts.Check("proof1", "whatever") {
		t.Fatal("unbound token should pass with any caller session")
	}
	// 过期 token 应失败
	ts2 := NewTokenStore(newTestCache(), -time.Second)
	ts2.Set("expired", 1, "s")
	if ts2.Check("expired", "s") {
		t.Fatal("expired token should fail")
	}
	if ts2.Has("expired") {
		t.Fatal("expired token Has should fail")
	}
	// Take 一次性
	if _, ok := ts.Take("tokA"); !ok {
		t.Fatal("take should succeed")
	}
	if ts.Check("tokA", "sessA") {
		t.Fatal("taken token should be gone")
	}
}
