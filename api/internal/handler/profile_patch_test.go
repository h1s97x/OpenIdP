package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/h1s97x/openidp/api/internal/models"
)

// TestPatchProfileFieldSemantics 覆盖 PATCH /me/profile 的字段语义：
//   - 未传 address 不得改动（旧实现无条件写回，漏传即清空）；
//   - 显式传空串才是清空；
//   - 传了不同的 email 必须显式拒绝，而不是静默忽略（避免旧客户端
//     「以为改了其实没改」）；同值 email 放行。
func TestPatchProfileFieldSemantics(t *testing.T) {
	h, _ := newTestHandler(t)
	alice := createTestUser(t, h.db, "alice", "Str0ngPassw0rd!")
	alice.Address = "杭州市"
	if _, err := h.db.NewUpdate().Model(alice).WherePK().Exec(context.Background()); err != nil {
		t.Fatalf("seed address: %v", err)
	}
	sessID, csrf := loginAs(t, h, alice)

	reload := func() models.User {
		var u models.User
		if err := h.db.NewSelect().Model(&u).Where("id = ?", alice.ID).Scan(context.Background()); err != nil {
			t.Fatalf("reload user: %v", err)
		}
		return u
	}

	// 只改昵称：address 必须原样保留。
	if w := call(h, sessID, csrf, "PATCH", "/api/v1/me/profile", `{"displayName":"Alice2"}`); w.Code != http.StatusOK {
		t.Fatalf("patch displayName status=%d body=%s", w.Code, w.Body.String())
	}
	if u := reload(); u.DisplayName != "Alice2" || u.Address != "杭州市" {
		t.Fatalf("omitted address must be kept, got displayName=%q address=%q", u.DisplayName, u.Address)
	}

	// 显式传空串：清空 address。
	if w := call(h, sessID, csrf, "PATCH", "/api/v1/me/profile", `{"address":""}`); w.Code != http.StatusOK {
		t.Fatalf("patch empty address status=%d body=%s", w.Code, w.Body.String())
	}
	if u := reload(); u.Address != "" {
		t.Fatalf("explicit empty address must clear it, got %q", u.Address)
	}

	// 改邮箱：必须仍然显式拒绝，且邮箱不被改动。
	w := call(h, sessID, csrf, "PATCH", "/api/v1/me/profile", `{"email":"attacker@example.com"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("changing email via profile must be rejected, status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v (%s)", err, w.Body.String())
	}
	if body["code"] != "email.use_change_endpoint" {
		t.Fatalf("错误码 = %v; want email.use_change_endpoint", body["code"])
	}
	if u := reload(); u.Email != alice.Email {
		t.Fatalf("email must not change, got %q want %q", u.Email, alice.Email)
	}

	// 同值（含大小写差异）邮箱不算修改，应放行：
	// 比较走 strings.EqualFold，与 POST /me/email 先归一化再比较的口径一致，
	// 避免客户端把同一地址换个大小写就收到「请走更换流程」的误导性 400。
	if w := call(h, sessID, csrf, "PATCH", "/api/v1/me/profile", `{"email":"`+alice.Email+`"}`); w.Code != http.StatusOK {
		t.Fatalf("unchanged email should be accepted, status=%d body=%s", w.Code, w.Body.String())
	}
	if w := call(h, sessID, csrf, "PATCH", "/api/v1/me/profile", `{"email":"`+strings.ToUpper(alice.Email)+`"}`); w.Code != http.StatusOK {
		t.Fatalf("case-different same email should be accepted, status=%d body=%s", w.Code, w.Body.String())
	}
}
