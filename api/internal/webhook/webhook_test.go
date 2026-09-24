package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h1s97x/openidp/api/internal/event"
)

func TestSenderDeliversAndSigns(t *testing.T) {
	var mu sync.Mutex
	received := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = r.Header.Get("X-OpenIdP-Signature")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := New(Config{URLs: []string{ts.URL}, Secret: "topsecret"})
	bus := event.New()
	stop := s.Attach(bus)
	defer stop()

	bus.Publish(context.TODO(), event.Data{Type: "security.auth.login", UserID: 42})

	// delivery is async; poll briefly
	for i := 0; i < 100; i++ {
		mu.Lock()
		got := received
		mu.Unlock()
		if got != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if received == "" {
		t.Fatal("expected webhook signature header")
	}
	if len(received) != 64 || !isHex(received) {
		t.Fatalf("unexpected signature %q", received)
	}
}

func TestSenderTargets(t *testing.T) {
	s := New(Config{URLs: []string{"http://a"}})
	if len(s.Targets()) != 1 {
		t.Fatalf("expected 1 target, got %d", len(s.Targets()))
	}
	s.SetTargets([]string{"http://b", "http://c"})
	if len(s.Targets()) != 2 {
		t.Fatalf("expected 2 targets after update")
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
