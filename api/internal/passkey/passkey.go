// Package passkey implements WebAuthn 通行密钥 (passkey) authentication
// ceremonies backed by the database, using github.com/go-webauthn/webauthn.
package passkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/uptrace/bun"

	"github.com/h1s97x/openidp/api/internal/cache"
	"github.com/h1s97x/openidp/api/internal/db"
	"github.com/h1s97x/openidp/api/internal/models"
)

// Config describes the resolved WebAuthn relying-party configuration for a
// single ceremony. Enabled=false 表示未配置/不允许使用通行密钥（不启用）。
// origin 优先取系统设置中的站点 URL，其次按当前访问域名兜底推导。
type Config struct {
	Enabled bool
	RPID    string
	Origin  string
	RPName  string
	// Origins 额外的允许来源（如自定义域名）；为空时仅使用 Origin。
	Origins []string
}

// Service wraps the WebAuthn RP resolution and the ceremony store.
//
// 仪式（ceremony）状态存放在共享缓存（Redis 可用时使用，否则内存）而不是进程内
// map：多实例部署时 begin 在 A、finish 在 B 也能正常完成，与项目其余共享状态
// （TokenStore / 限流器 / consent 缓存）保持一致。
type Service struct {
	db      *bun.DB
	cache   cache.Cache
	resolve func(originHint string) Config
}

// ceremony 是一次通行密钥仪式的中间状态。
//
// 字段必须导出并带 json 标签：store/take 用 encoding/json 把它序列化进共享缓存，
// 而 encoding/json 只编解码导出字段。此前字段全部未导出，json.Marshal 得到的是
// 空对象 "{}"，取出后 Kind 恒为空串，finish 一律以 "invalid ceremony" 失败，
// 导致通行密钥注册（以及登录）永远无法完成。
type ceremony struct {
	Kind      string               `json:"kind"` // login | register | loginDiscoverable
	UserID    int64                `json:"userId"`
	Session   webauthn.SessionData `json:"session"`
	RPID      string               `json:"rpId"`
	Origin    string               `json:"origin"`
	RPName    string               `json:"rpName"`
	ExpiresAt time.Time            `json:"expiresAt"`
}

// ceremonyTTL 是一次通行密钥仪式的有效期（begin 后须在此时间内 finish）。
const ceremonyTTL = 5 * time.Minute

// New creates the WebAuthn service. resolve 在每次 begin/finish 时被调用，
// originHint 为本次请求推导出的当前访问源（未配置时兑底使用），用于动态解析
// 依赖方 URL（优先系统设置、其次当前访问域名兑底）。
// c 是共享缓存，用于跨实例保存仪式状态（nil 时回退为进程内存储）。
func New(db *bun.DB, resolve func(originHint string) Config, c cache.Cache) *Service {
	if c == nil {
		c = cache.NewMemory()
	}
	return &Service{
		db:      db,
		cache:   c,
		resolve: resolve,
	}
}

// newWebAuthn builds a webauthn instance for the given relying-party config.
func newWebAuthn(rpID, origin, rpName string, origins ...string) (*webauthn.WebAuthn, error) {
	rpOrigins := []string{origin}
	for _, o := range origins {
		if strings.TrimSpace(o) == "" {
			continue
		}
		dupe := false
		for _, e := range rpOrigins {
			if strings.EqualFold(strings.TrimRight(e, "/"), strings.TrimRight(strings.TrimSpace(o), "/")) {
				dupe = true
				break
			}
		}
		if !dupe {
			rpOrigins = append(rpOrigins, strings.TrimSpace(o))
		}
	}
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpName,
		RPOrigins:     rpOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationRequired,
		},
	})
}

// BeginLogin starts a passkey authentication ceremony for a user.
// It returns the ceremonyID and the PublicKeyCredentialRequestOptions JSON.
func (s *Service) BeginLogin(userID int64, originHint string) (ceremonyID string, optionsJSON []byte, err error) {
	cfg := s.resolve(originHint)
	if !cfg.Enabled || cfg.RPID == "" || cfg.Origin == "" {
		return "", nil, errors.New("passkey: not configured")
	}
	wa, err := newWebAuthn(cfg.RPID, cfg.Origin, cfg.RPName, cfg.Origins...)
	if err != nil {
		return "", nil, err
	}
	u, err := s.loadUser(userID)
	if err != nil {
		return "", nil, err
	}
	assertion, session, err := wa.BeginLogin(u)
	if err != nil {
		return "", nil, err
	}
	ceremonyID = newID()
	s.store(ceremony{Kind: "login", UserID: userID, Session: *session, RPID: cfg.RPID, Origin: cfg.Origin, RPName: cfg.RPName, ExpiresAt: time.Now().Add(ceremonyTTL)}, ceremonyID)
	optionsJSON, err = json.Marshal(assertion)
	return ceremonyID, optionsJSON, err
}

// BeginDiscoverableLogin starts a usernameless passkey login ceremony.
// It returns the ceremonyID and the PublicKeyCredentialRequestOptions JSON.
func (s *Service) BeginDiscoverableLogin(originHint string) (ceremonyID string, optionsJSON []byte, err error) {
	cfg := s.resolve(originHint)
	if !cfg.Enabled || cfg.RPID == "" || cfg.Origin == "" {
		return "", nil, errors.New("passkey: not configured")
	}
	wa, err := newWebAuthn(cfg.RPID, cfg.Origin, cfg.RPName, cfg.Origins...)
	if err != nil {
		return "", nil, err
	}
	assertion, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		return "", nil, err
	}
	ceremonyID = newID()
	s.store(ceremony{Kind: "loginDiscoverable", UserID: 0, Session: *session, RPID: cfg.RPID, Origin: cfg.Origin, RPName: cfg.RPName, ExpiresAt: time.Now().Add(ceremonyTTL)}, ceremonyID)
	optionsJSON, err = json.Marshal(assertion)
	return ceremonyID, optionsJSON, err
}

// FinishDiscoverableLogin completes a usernameless passkey login ceremony,
// resolving the user from the credential rawID. Returns the authenticated user ID.
func (s *Service) FinishDiscoverableLogin(ceremonyID string, credentialJSON json.RawMessage) (int64, error) {
	c, ok := s.take(ceremonyID)
	if !ok || c.Kind != "loginDiscoverable" {
		return 0, errors.New("passkey: invalid ceremony")
	}
	wa, err := newWebAuthn(c.RPID, c.Origin, c.RPName)
	if err != nil {
		return 0, err
	}
	req := mustHTTPRequest(credentialJSON)
	user, cred, err := wa.FinishPasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		return s.lookupByCredential(rawID)
	}, c.Session, req)
	if err != nil {
		return 0, err
	}
	userID := userIDOf(user)
	if userID == 0 {
		return 0, errors.New("passkey: unknown user")
	}
	if err := s.updateCounter(userID, cred); err != nil {
		return 0, err
	}
	return userID, nil
}

// BeginRegistration starts a passkey registration ceremony (bind new key).
func (s *Service) BeginRegistration(userID int64, originHint string) (ceremonyID string, optionsJSON []byte, err error) {
	cfg := s.resolve(originHint)
	if !cfg.Enabled || cfg.RPID == "" || cfg.Origin == "" {
		return "", nil, errors.New("passkey: not configured")
	}
	wa, err := newWebAuthn(cfg.RPID, cfg.Origin, cfg.RPName, cfg.Origins...)
	if err != nil {
		return "", nil, err
	}
	u, err := s.loadUser(userID)
	if err != nil {
		return "", nil, err
	}
	creation, session, err := wa.BeginRegistration(u)
	if err != nil {
		return "", nil, err
	}
	ceremonyID = newID()
	s.store(ceremony{Kind: "register", UserID: userID, Session: *session, RPID: cfg.RPID, Origin: cfg.Origin, RPName: cfg.RPName, ExpiresAt: time.Now().Add(ceremonyTTL)}, ceremonyID)
	optionsJSON, err = json.Marshal(creation)
	return ceremonyID, optionsJSON, err
}

// FinishLogin completes a login ceremony. Returns the authenticated user ID.
func (s *Service) FinishLogin(ceremonyID string, credentialJSON json.RawMessage) (int64, error) {
	c, ok := s.take(ceremonyID)
	if !ok || c.Kind != "login" {
		return 0, errors.New("passkey: invalid ceremony")
	}
	wa, err := newWebAuthn(c.RPID, c.Origin, c.RPName)
	if err != nil {
		return 0, err
	}
	u, err := s.loadUser(c.UserID)
	if err != nil {
		return 0, err
	}
	req := mustHTTPRequest(credentialJSON)
	cred, err := wa.FinishLogin(u, c.Session, req)
	if err != nil {
		return 0, err
	}
	if err := s.updateCounter(c.UserID, cred); err != nil {
		return 0, err
	}
	return c.UserID, nil
}

// FinishRegistration completes a registration ceremony and persists the credential.
func (s *Service) FinishRegistration(ceremonyID string, name string, credentialJSON json.RawMessage) (int64, error) {
	c, ok := s.take(ceremonyID)
	if !ok || c.Kind != "register" {
		return 0, errors.New("passkey: invalid ceremony")
	}
	wa, err := newWebAuthn(c.RPID, c.Origin, c.RPName)
	if err != nil {
		return 0, err
	}
	u, err := s.loadUser(c.UserID)
	if err != nil {
		return 0, err
	}
	req := mustHTTPRequest(credentialJSON)
	cred, err := wa.FinishRegistration(u, c.Session, req)
	if err != nil {
		return 0, err
	}
	if err := s.persistCredential(c.UserID, name, cred); err != nil {
		return 0, err
	}
	return c.UserID, nil
}

// loadUser wraps models.User as a webauthn.User with passkeys.
//
// 注意：这里只加载用户本身，不预加载其通行密钥——userAdapter.WebAuthnCredentials
// 会在需要时按需查询。此前这里有一段查询 passkeys 的代码，但结果赋给局部变量后
// 从未使用（且错误处理分支为空），等于每次通行密钥操作都白跑一次数据库查询。
func (s *Service) loadUser(userID int64) (*userAdapter, error) {
	var u models.User
	if err := s.db.NewSelect().Model(&u).Where("id = ?", userID).Scan(context.Background()); err != nil {
		return nil, err
	}
	return &userAdapter{user: &u, db: s.db}, nil
}

// lookupByCredential finds the user that owns a credential (for discoverable login).
func (s *Service) lookupByCredential(rawID []byte) (*userAdapter, error) {
	var pk models.Passkey
	err := s.db.NewSelect().Model(&pk).Where("credential_id = ?", rawID).Scan(context.Background())
	if err != nil {
		return nil, err
	}
	return s.loadUser(pk.UserID)
}

// userIDOf extracts the user ID from a webauthn.User adapter.
func userIDOf(u webauthn.User) int64 {
	if a, ok := u.(*userAdapter); ok && a != nil && a.user != nil {
		return a.user.ID
	}
	return 0
}

// ceremonyKey 是仪式状态在共享缓存中的键前缀。
const ceremonyKey = "passkey:ceremony:"

// store 持久化一次仪式状态（带 TTL，过期由缓存自动回收，
// 不会因 begin 后从不 finish 而无限增长）。
func (s *Service) store(c ceremony, id string) {
	b, err := json.Marshal(c)
	if err != nil {
		return
	}
	s.cache.Set(context.Background(), ceremonyKey+id, string(b), ceremonyTTL)
}

// take 原子地取出并删除一次仪式状态（避免并发重复消费同一仪式）。
func (s *Service) take(id string) (ceremony, bool) {
	var c ceremony
	raw, ok := s.cache.GetDel(context.Background(), ceremonyKey+id)
	if !ok {
		return c, false
	}
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return ceremony{}, false
	}
	if time.Now().After(c.ExpiresAt) {
		return c, false
	}
	return c, true
}

// PeekKind returns the ceremony kind without consuming it, so callers can
// dispatch to the correct finish handler (login vs. discoverable login).
func (s *Service) PeekKind(id string) string {
	if id == "" {
		return ""
	}
	raw, ok := s.cache.Get(context.Background(), ceremonyKey+id)
	if !ok {
		return ""
	}
	var c ceremony
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return ""
	}
	if time.Now().After(c.ExpiresAt) {
		return ""
	}
	return c.Kind
}

// updateCounter refreshes the sign counter after a successful login.
func (s *Service) updateCounter(userID int64, cred *webauthn.Credential) error {
	_, err := s.db.NewUpdate().Model((*models.Passkey)(nil)).
		Set("sign_count = ?", cred.Authenticator.SignCount).
		Set("last_used_at = ?", db.Now()).
		Where("user_id = ? AND credential_id = ?", userID, cred.ID).
		Exec(context.Background())
	return err
}

// persistCredential stores a newly registered passkey.
//
// 四个 JSON 列写入的是「待落库的 JSON 报文」本身（json.RawMessage）：bun 对
// type:json 列会再做一次 json.Marshal，若这里传 []byte，落库结果会变成
// base64 字符串，读回时按对象解析失败，凭据标志位与签名计数全部丢失。
func (s *Service) persistCredential(userID int64, name string, cred *webauthn.Credential) error {
	transport := mustMarshalJSON(cred.Transport)
	flags := mustMarshalJSON(cred.Flags)
	auth := mustMarshalJSON(cred.Authenticator)
	att := mustMarshalJSON(cred.Attestation)
	now := db.Now()
	if name == "" {
		name = "通行密钥"
	}
	pk := &models.Passkey{
		UserID:          userID,
		CredentialID:    cred.ID,
		Name:            name,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transport:       transport,
		Flags:           flags,
		Authenticator:   auth,
		Attestation:     att,
		SignCount:       cred.Authenticator.SignCount,
		CreatedAt:       now,
		LastUsedAt:      now,
	}
	_, err := s.db.NewInsert().Model(pk).Exec(context.Background())
	return err
}

// List returns the passkeys bound to a user (JSON-friendly view).
func (s *Service) List(userID int64) ([]map[string]any, error) {
	var creds []models.Passkey
	if err := s.db.NewSelect().Model(&creds).Where("user_id = ?", userID).Order("created_at DESC").Scan(context.Background()); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		out = append(out, map[string]any{
			"id":              fmt.Sprintf("%x", c.CredentialID),
			"name":            c.Name,
			"createdAt":       c.CreatedAt,
			"lastUsedAt":      c.LastUsedAt,
			"attestationType": c.AttestationType,
		})
	}
	return out, nil
}

// Delete removes a passkey owned by the user.
func (s *Service) Delete(userID int64, credentialHex string) error {
	var id []byte
	if _, err := fmt.Sscanf(credentialHex, "%x", &id); err != nil {
		return errors.New("invalid credential id")
	}
	_, err := s.db.NewDelete().Model((*models.Passkey)(nil)).
		Where("user_id = ? AND credential_id = ?", userID, id).Exec(context.Background())
	return err
}

// userAdapter implements webauthn.User backed by models.User + Passkey.
type userAdapter struct {
	user *models.User
	db   *bun.DB
}

func (u *userAdapter) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("user-%d", u.user.ID))
}

func (u *userAdapter) WebAuthnName() string {
	return u.user.Username
}

func (u *userAdapter) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.user.Username
}

func (u *userAdapter) WebAuthnCredentials() []webauthn.Credential {
	var creds []models.Passkey
	_ = u.db.NewSelect().Model(&creds).Where("user_id = ?", u.user.ID).Scan(context.Background())
	out := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		var cred webauthn.Credential
		cred.ID = c.CredentialID
		cred.PublicKey = c.PublicKey
		cred.AttestationType = c.AttestationType
		decodeStoredJSON(c.Transport, &cred.Transport)
		decodeStoredJSON(c.Flags, &cred.Flags)
		decodeStoredJSON(c.Authenticator, &cred.Authenticator)
		decodeStoredJSON(c.Attestation, &cred.Attestation)
		out = append(out, cred)
	}
	return out
}

// mustMarshalJSON 序列化要写入 type:json 列的值，失败时回退为 null 而不是
// 写入半截报文（半截 JSON 会让整行在读取时永久解析失败）。
func mustMarshalJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// decodeStoredJSON 解码通行密钥的 JSON 列。
//
// 该列在 bun 中声明为 type:json，bun 写入时会对字段再做一次 json.Marshal。
// 旧实现的字段类型是 []byte：业务侧先 json.Marshal 得到 JSON 字节，bun 再把它
// 当字节切片编成 base64 字符串，落库结果形如 "<base64(JSON)>"。读回时按对象
// 解析必然失败（目标是字符串而非对象），而旧实现用 _ 吞掉了这个错误，于是
// Flags/Authenticator 恒为零值。
//
// 后果：登录校验拿零值的 BackupEligible 与认证器上报的 BE 标志比对，
// go-webauthn 直接以「Backup Eligible flag inconsistency」拒绝——表现为
// 「添加通行密钥成功，登录必定 400」；注册流程不读这些字段，因此一切正常。
//
// 这里同时兼容两种落库格式：新格式（JSON 对象本身）与历史格式（base64 字符串），
// 升级前已绑定的通行密钥无需删除重绑即可登录。
func decodeStoredJSON(raw json.RawMessage, dst any) {
	if len(raw) == 0 {
		return
	}
	if err := json.Unmarshal(raw, dst); err == nil {
		return
	}
	// 历史数据：JSON 字节被 bun 额外编码成 base64 字符串。
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return
	}
	_ = json.Unmarshal(decoded, dst)
}
