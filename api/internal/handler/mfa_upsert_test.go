package handler

import (
	"testing"
	"time"

	"github.com/h1s97x/openidp/api/internal/models"
)

// TestSaveMFAUpsertIsDialectAgnostic 验证 MFA 记录写入不依赖 UPSERT 语法：
// 连续两次保存都只应对应一条记录（按 user_id 唯一），且第二次覆盖密钥。
func TestSaveMFAUpsertIsDialectAgnostic(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "mfadialect", "Str0ngPassw0rd!")

	first := &models.MFA{UserID: u.ID, Secret: "secret-one", UpdatedAt: time.Now().UTC()}
	if err := h.saveMFA(first); err != nil {
		t.Fatalf("first saveMFA: %v", err)
	}
	second := &models.MFA{UserID: u.ID, Secret: "secret-two", UpdatedAt: time.Now().UTC()}
	if err := h.saveMFA(second); err != nil {
		t.Fatalf("second saveMFA: %v", err)
	}

	got := h.loadMFA(u.ID)
	if got == nil {
		t.Fatal("loadMFA returned nil after save")
	}
	if got.Secret != "secret-two" {
		t.Fatalf("secret = %q; want secret-two (second save should overwrite)", got.Secret)
	}
	if got.UserID != u.ID {
		t.Fatalf("userID = %d; want %d", got.UserID, u.ID)
	}
}

// TestSaveMFAPreservesRecoveryCodes 验证重复 begin 不会把已生成的恢复码清空。
func TestSaveMFAPreservesRecoveryCodes(t *testing.T) {
	h, _ := newTestHandler(t)
	u := createTestUser(t, h.db, "mfakeepcodes", "Str0ngPassw0rd!")

	first := &models.MFA{UserID: u.ID, Secret: "s1", RecoveryCodes: []byte("[\"a-b-c\"]"), UpdatedAt: time.Now().UTC()}
	if err := h.saveMFA(first); err != nil {
		t.Fatalf("first saveMFA: %v", err)
	}
	before := string(h.loadMFA(u.ID).RecoveryCodes)
	if before == "" {
		t.Fatal("recovery codes lost on first save")
	}
	// 模拟用户再次调用 begin：新记录未携带恢复码，应保留库中已有值。
	second := &models.MFA{UserID: u.ID, Secret: "s2", UpdatedAt: time.Now().UTC()}
	if err := h.saveMFA(second); err != nil {
		t.Fatalf("second saveMFA: %v", err)
	}

	after := string(h.loadMFA(u.ID).RecoveryCodes)
	if after != before {
		t.Fatalf("recovery codes changed: %q -> %q; want preserved", before, after)
	}
}
