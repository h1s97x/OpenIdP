package event

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor 等待条件成立（派发是异步的，测试需要等待监听器执行）。
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for listeners to run")
}

func TestBusPublishSubscribe(t *testing.T) {
	b := New()
	var mu sync.Mutex
	var got []Data

	stop := b.Subscribe("auth.login", func(_ context.Context, e Data) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	})
	defer stop()

	b.Publish(context.Background(), Data{Type: "auth.login", UserID: 7})
	b.Publish(context.Background(), Data{Type: "other", UserID: 9})
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 1
	})

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("expected 1 delivered event, got %d", len(got))
	}
	if got[0].UserID != 7 {
		t.Fatalf("expected user 7, got %d", got[0].UserID)
	}
}

func TestBusStopUnsubscribes(t *testing.T) {
	b := New()
	var count atomic.Int32
	stop := b.Subscribe("x", func(_ context.Context, _ Data) { count.Add(1) })
	b.Publish(context.Background(), Data{Type: "x"})
	waitFor(t, func() bool { return count.Load() == 1 })
	stop()
	b.Publish(context.Background(), Data{Type: "x"})
	time.Sleep(100 * time.Millisecond)
	if got := count.Load(); got != 1 {
		t.Fatalf("expected 1 event after unsubscribe, got %d", got)
	}
}

func TestBusMultipleListeners(t *testing.T) {
	b := New()
	var c1, c2 atomic.Int32
	defer b.Subscribe("m", func(_ context.Context, _ Data) { c1.Add(1) })()
	defer b.Subscribe("m", func(_ context.Context, _ Data) { c2.Add(1) })()

	b.Publish(context.Background(), Data{Type: "m"})
	waitFor(t, func() bool { return c1.Load() == 1 && c2.Load() == 1 })
}

func TestPublishDoesNotBlockOnSlowListener(t *testing.T) {
	b := New()
	var started atomic.Int32
	b.Subscribe("slow", func(_ context.Context, _ Data) {
		started.Add(1)
		time.Sleep(300 * time.Millisecond)
	})
	done := make(chan struct{})
	go func() {
		b.Publish(context.Background(), Data{Type: "slow"})
		close(done)
	}()
	select {
	case <-done:
		// 派发立即返回，不等待监听器执行完毕。
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a slow listener")
	}
	waitFor(t, func() bool { return started.Load() == 1 })
}

func TestNilBusSafe(t *testing.T) {
	var b *Bus
	stop := b.Subscribe("x", func(_ context.Context, _ Data) {})
	stop()
	b.Publish(context.Background(), Data{Type: "x"})
	if b.Has("x") {
		t.Fatal("nil bus should report no listeners")
	}
}
