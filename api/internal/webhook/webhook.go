// Package webhook delivers authentication and security events to external
// systems (custom HTTP endpoints, enterprise WeChat, Feishu) by subscribing to
// the in-process event bus. Delivery is asynchronous and fire-and-forget with
// a bounded timeout; failures are logged and never block the caller.
//
// Webhook targets are configured via OPENIDP_WEBHOOK_URLS (comma-separated) and
// OPENIDP_WEBHOOK_SECRET (optional HMAC signing secret).
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/h1s97x/openidp/api/internal/event"
)

// Config describes the webhook delivery settings.
type Config struct {
	// URLs is the list of endpoint URLs to notify.
	URLs []string
	// Secret, when non-empty, is used to sign the request body (X-OpenIdP-Signature).
	Secret string
	// Timeout bounds each delivery attempt.
	Timeout time.Duration
}

// Sender delivers events to configured webhook endpoints.
type Sender struct {
	cfg     Config
	client  *http.Client
	mu      sync.RWMutex
	targets []string
}

// New creates a webhook Sender. It does not subscribe until Attach is called.
func New(cfg Config) *Sender {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &Sender{
		cfg:     cfg,
		targets: append([]string(nil), cfg.URLs...),
		client:  &http.Client{Timeout: cfg.Timeout},
	}
}

// Attach subscribes the sender to the event bus for all "security.*" events.
// Returns a stop function to detach the listener.
func (s *Sender) Attach(bus *event.Bus) (stop func()) {
	return bus.Subscribe("security.*", s.Deliver)
}

// Deliver sends a single security event to all configured endpoints.
func (s *Sender) Deliver(_ context.Context, e event.Data) {
	s.send(e)
}

// send delivers a single event to all targets asynchronously.
func (s *Sender) send(e event.Data) {
	body, err := json.Marshal(map[string]any{
		"type":    e.Type,
		"userId":  e.UserID,
		"payload": e.Payload,
		"sentAt":  time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return
	}
	s.mu.RLock()
	targets := append([]string(nil), s.targets...)
	s.mu.RUnlock()
	for _, url := range targets {
		go s.deliver(url, body)
	}
}

func (s *Sender) deliver(url string, body []byte) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("❌ [Webhook] 构建请求失败: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.Secret != "" {
		req.Header.Set("X-OpenIdP-Signature", sign(body, s.cfg.Secret))
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	defer cancel()
	resp, err := s.client.Do(req.WithContext(ctx))
	if err != nil {
		log.Printf("❌ [Webhook] 投递到 %s 失败: %v", url, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("⚠️ [Webhook] 投递到 %s 返回非 2xx: %s", url, resp.Status)
	}
}

// SetTargets updates the list of webhook endpoints at runtime.
func (s *Sender) SetTargets(urls []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets = append([]string(nil), urls...)
}

// Targets returns the current list of webhook endpoints.
func (s *Sender) Targets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.targets...)
}

func sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
