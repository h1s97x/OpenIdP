package passkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"

	"github.com/h1s97x/openidp/api/internal/models"
)

// ---------------------------------------------------------------------------
// 通行密钥「注册 → 登录」全链路回归测试（内置虚拟认证器）
//
// 背景：通行密钥登录（POST /api/v1/session/passkey/finish）线上稳定返回 400，
// 而注册（POST /api/v1/me/passkeys/finish）正常。二者共用同一套仪式状态与
// 同一份存储，仅登录走「可发现凭据（usernameless）」分支，且 finish 前多一次
// PeekKind 派发。仅靠读代码无法确定失败点，因此这里实现一个最小软件认证器，
// 真实走完 begin/finish 的编解码与校验链路，让失败点自己暴露出来，并作为
// 后续重构的回归网。
// ---------------------------------------------------------------------------

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
	testRPName = "OpenIdP"
)

// testConfig 固定依赖方配置，避免测试受系统设置影响。
func testConfig(_ string) Config {
	return Config{Enabled: true, RPID: testRPID, Origin: testOrigin, RPName: testRPName}
}

func newPasskeyTestDB(t *testing.T) *bun.DB {
	t.Helper()
	sqldb, err := sql.Open(sqliteshim.DriverName(),
		"file:"+filepath.Join(t.TempDir(), "passkey.db")+"?cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	bdb := bun.NewDB(sqldb, sqlitedialect.New())
	t.Cleanup(func() { _ = bdb.Close() })

	ctx := context.Background()
	for _, m := range []any{(*models.User)(nil), (*models.Passkey)(nil)} {
		if _, err := bdb.NewCreateTable().Model(m).IfNotExists().Exec(ctx); err != nil {
			t.Fatalf("create table %T: %v", m, err)
		}
	}
	return bdb
}

func insertTestUser(t *testing.T, db *bun.DB, name string) *models.User {
	t.Helper()
	now := time.Now().UTC()
	u := &models.User{Subject: name, Username: name, CreatedAt: now, UpdatedAt: now}
	if _, err := db.NewInsert().Model(u).Exec(context.Background()); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return u
}

// ---- 虚拟认证器 ----

// softAuthenticator 按 WebAuthn 规范拼装 attestationObject 与断言签名，
// 用于在无浏览器环境下复现完整的通行密钥仪式。
type softAuthenticator struct {
	key       *ecdsa.PrivateKey
	credID    []byte
	aaguid    []byte
	signCount uint32
	// flags 为认证器数据标志位。注册与登录必须保持一致，否则服务端的
	// BackupEligible 标志一致性校验会直接拒绝登录。
	flags byte
}

const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
	flagBE = 0x08 // backup eligible
	flagAT = 0x40 // attested credential data present
)

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("generate credential id: %v", err)
	}
	return &softAuthenticator{
		key:    key,
		credID: credID,
		aaguid: make([]byte, 16),
		flags:  flagUP | flagUV | flagBE,
	}
}

// coseKey 编码 COSE_Key（EC2 / P-256 / ES256）。
func (a *softAuthenticator) coseKey() []byte {
	x := a.key.X.FillBytes(make([]byte, 32))
	y := a.key.Y.FillBytes(make([]byte, 32))
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20)
	out = append(out, y...)
	return out
}

func (a *softAuthenticator) makeAuthData(rpID string, flags byte, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := make([]byte, 0, 37+len(attested))
	out = append(out, h[:]...)
	out = append(out, flags)
	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, a.signCount)
	out = append(out, c...)
	out = append(out, attested...)
	return out
}

func (a *softAuthenticator) attestedCredentialData() []byte {
	out := make([]byte, 0, 16+2+len(a.credID)+len(a.coseKey()))
	out = append(out, a.aaguid...)
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(a.credID)))
	out = append(out, l...)
	out = append(out, a.credID...)
	out = append(out, a.coseKey()...)
	return out
}

// cborByteString 生成 CBOR byte string 头（major type 2）。
func cborByteString(b []byte) []byte {
	var head []byte
	switch n := len(b); {
	case n < 24:
		head = []byte{byte(0x40 + n)}
	case n < 256:
		head = []byte{0x58, byte(n)}
	default:
		head = []byte{0x59, byte(n >> 8), byte(n & 0xff)}
	}
	return append(head, b...)
}

// attestationObject 生成 fmt=none 的 CBOR 认证对象。
func (a *softAuthenticator) attestationObject(authData []byte) []byte {
	out := []byte{0xa3}
	out = append(out, 0x63, 'f', 'm', 't')
	out = append(out, 0x64, 'n', 'o', 'n', 'e')
	out = append(out, 0x67, 'a', 't', 't', 'S', 't', 'm', 't')
	out = append(out, 0xa0)
	out = append(out, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a')
	out = append(out, cborByteString(authData)...)
	return out
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func clientDataJSON(typ, challenge, origin string) []byte {
	b, err := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		panic(err)
	}
	return b
}

// createCredential 模拟 navigator.credentials.create()。
func (a *softAuthenticator) createCredential(t *testing.T, optionsJSON []byte, origin string) json.RawMessage {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		t.Fatalf("解析注册参数: %v", err)
	}
	if opts.PublicKey.Challenge == "" || opts.PublicKey.RP.ID == "" {
		t.Fatalf("注册参数缺少 challenge/rp.id: %s", optionsJSON)
	}
	cd := clientDataJSON("webauthn.create", opts.PublicKey.Challenge, origin)
	authData := a.makeAuthData(opts.PublicKey.RP.ID, a.flags|flagAT, a.attestedCredentialData())
	b, err := json.Marshal(map[string]any{
		"id":    b64url(a.credID),
		"rawId": b64url(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64url(cd),
			"attestationObject": b64url(a.attestationObject(authData)),
		},
		"clientExtensionResults": map[string]any{},
	})
	if err != nil {
		t.Fatalf("序列化注册响应: %v", err)
	}
	return b
}

// assertCredential 模拟 navigator.credentials.get()。
func (a *softAuthenticator) assertCredential(t *testing.T, optionsJSON []byte, origin string, userHandle []byte) json.RawMessage {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge      string `json:"challenge"`
			RelyingPartyID string `json:"rpId"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		t.Fatalf("解析断言参数: %v", err)
	}
	if opts.PublicKey.Challenge == "" || opts.PublicKey.RelyingPartyID == "" {
		t.Fatalf("断言参数缺少 challenge/rpId: %s", optionsJSON)
	}
	cd := clientDataJSON("webauthn.get", opts.PublicKey.Challenge, origin)

	a.signCount++
	authData := a.makeAuthData(opts.PublicKey.RelyingPartyID, a.flags, nil)

	cdHash := sha256.Sum256(cd)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	// 断言签名是 ASN.1 DER 编码的 ECDSA 签名（CTAP2 认证器返回该格式，
	// go-webauthn 的 EC2 校验也按 DER 解析），不是裸 r||s。
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("签名断言: %v", err)
	}

	resp := map[string]any{
		"id":    b64url(a.credID),
		"rawId": b64url(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64url(cd),
			"authenticatorData": b64url(authData),
			"signature":         b64url(sig),
		},
		"clientExtensionResults": map[string]any{},
	}
	if len(userHandle) > 0 {
		resp["response"].(map[string]any)["userHandle"] = b64url(userHandle)
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("序列化断言响应: %v", err)
	}
	return b
}

// ---- 端到端用例 ----

// TestRegisterThenDiscoverableLogin 复现「添加通行密钥成功、登录失败」的链路。
func TestRegisterThenDiscoverableLogin(t *testing.T) {
	db := newPasskeyTestDB(t)
	svc := New(db, testConfig, nil)
	u := insertTestUser(t, db, "alice")
	auth := newSoftAuthenticator(t)

	// 1. 注册：作为对照组，确认存储与编解码链路本身可用。
	regID, regOpts, err := svc.BeginRegistration(u.ID, testOrigin)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err := svc.FinishRegistration(regID, "测试密钥", auth.createCredential(t, regOpts, testOrigin)); err != nil {
		t.Fatalf("FinishRegistration（对照组，不应失败）: %v", err)
	}

	// 2. 可发现凭据登录：线上报 400 的正是这一步。
	loginID, loginOpts, err := svc.BeginDiscoverableLogin(testOrigin)
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	if kind := svc.PeekKind(loginID); kind != "loginDiscoverable" {
		t.Fatalf("PeekKind = %q, want loginDiscoverable", kind)
	}
	gotUserID, err := svc.FinishDiscoverableLogin(loginID,
		auth.assertCredential(t, loginOpts, testOrigin, []byte(fmt.Sprintf("user-%d", u.ID))))
	if err != nil {
		t.Fatalf("FinishDiscoverableLogin: %v", err)
	}
	if gotUserID != u.ID {
		t.Errorf("登录得到的用户 ID = %d, want %d", gotUserID, u.ID)
	}
}

// TestRegisterThenLoginByIdentifier 复现「输入账号后登录」的链路（非可发现凭据）。
func TestRegisterThenLoginByIdentifier(t *testing.T) {
	db := newPasskeyTestDB(t)
	svc := New(db, testConfig, nil)
	u := insertTestUser(t, db, "bob")
	auth := newSoftAuthenticator(t)

	regID, regOpts, err := svc.BeginRegistration(u.ID, testOrigin)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err := svc.FinishRegistration(regID, "测试密钥", auth.createCredential(t, regOpts, testOrigin)); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}

	loginID, loginOpts, err := svc.BeginLogin(u.ID, testOrigin)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if kind := svc.PeekKind(loginID); kind != "login" {
		t.Fatalf("PeekKind = %q, want login", kind)
	}
	gotUserID, err := svc.FinishLogin(loginID, auth.assertCredential(t, loginOpts, testOrigin, nil))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if gotUserID != u.ID {
		t.Errorf("登录得到的用户 ID = %d, want %d", gotUserID, u.ID)
	}
}

// ---------------------------------------------------------------------------
// 凭据标志位（BackupEligible）存储回归
//
// passkeys 的 transport/flags/authenticator/attestation 列在 bun 中声明为
// type:json，bun 写入时会对字段值再做一次 json.Marshal。旧实现的字段类型是
// []byte：业务侧先 json.Marshal 出 JSON 字节，bun 再把字节切片编成 base64
// 字符串，落库结果形如 "<base64(JSON)>"；读回时按对象解析必然失败，而旧实现
// 用 _ 吞掉错误，于是 Flags 恒为零值。
//
// 后果：登录校验用零值的 BackupEligible 与认证器上报的 BE 标志比对，
// go-webauthn 直接报「Backup Eligible flag inconsistency」，即线上
// 「添加通行密钥成功、登录必定 400」。注册流程不读这些字段，因此一切正常。
// ---------------------------------------------------------------------------

// TestCredentialFlagsSurviveStorage 标志位必须能从存储中原样读回。
func TestCredentialFlagsSurviveStorage(t *testing.T) {
	db := newPasskeyTestDB(t)
	svc := New(db, testConfig, nil)
	u := insertTestUser(t, db, "carol")
	auth := newSoftAuthenticator(t)

	regID, regOpts, err := svc.BeginRegistration(u.ID, testOrigin)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err := svc.FinishRegistration(regID, "测试密钥", auth.createCredential(t, regOpts, testOrigin)); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}

	// 落库内容必须是 JSON 对象，而不是被二次编码的 base64 字符串。
	var pk models.Passkey
	if err := db.NewSelect().Model(&pk).Where("user_id = ?", u.ID).Scan(context.Background()); err != nil {
		t.Fatalf("读取通行密钥: %v", err)
	}
	if len(pk.Flags) == 0 || pk.Flags[0] != '{' {
		t.Fatalf("flags 列应直接存 JSON 对象，实际=%s（首字节非 '{' 说明被二次编码）", pk.Flags)
	}

	adapter := &userAdapter{user: u, db: db}
	creds := adapter.WebAuthnCredentials()
	if len(creds) != 1 {
		t.Fatalf("凭据数量 = %d, want 1", len(creds))
	}
	if !creds[0].Flags.BackupEligible {
		t.Error("BackupEligible 读回为 false：标志位在存储往返中丢失，" +
			"会让登录校验因标志不一致被拒绝")
	}
	if !creds[0].Flags.UserPresent || !creds[0].Flags.UserVerified {
		t.Errorf("Flags 读回不完整: %+v", creds[0].Flags)
	}
}

// TestDecodeStoredJSONAcceptsLegacyDoubleEncoded 升级前写入的历史数据（JSON 字节
// 被 bun 二次编码成 base64 字符串）仍要能读出，否则已绑定的通行密钥全部失效。
func TestDecodeStoredJSONAcceptsLegacyDoubleEncoded(t *testing.T) {
	inner, err := json.Marshal(map[string]any{
		"userPresent":    true,
		"userVerified":   true,
		"backupEligible": true,
		"backupState":    false,
	})
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	// 复刻旧实现的落库结果：bun 对 []byte 做 json.Marshal → base64 字符串。
	legacy, err := json.Marshal([]byte(inner))
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}

	var flags struct {
		UserPresent    bool `json:"userPresent"`
		UserVerified   bool `json:"userVerified"`
		BackupEligible bool `json:"backupEligible"`
		BackupState    bool `json:"backupState"`
	}
	decodeStoredJSON(legacy, &flags)
	if !flags.BackupEligible || !flags.UserPresent || !flags.UserVerified || flags.BackupState {
		t.Errorf("历史格式解析失败: %+v", flags)
	}

	// 新格式（JSON 对象本身）同样要能解析
	decodeStoredJSON(inner, &flags)
	if !flags.BackupEligible {
		t.Error("新格式解析失败")
	}

	// 空值与非法内容不得 panic，且不应污染目标值
	decodeStoredJSON(nil, &flags)
	decodeStoredJSON(json.RawMessage(`"not-base64!!"`), &flags)
}
