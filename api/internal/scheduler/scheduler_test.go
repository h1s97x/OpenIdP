package scheduler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestSchedulerRunsJobs(t *testing.T) {
	s := New()
	var count atomic.Int32
	s.Every("test", 50*time.Millisecond, func(_ context.Context) error {
		count.Add(1)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	stop := s.Start(ctx)
	defer stop()

	// wait for at least one run + interval runs
	time.Sleep(300 * time.Millisecond)
	if count.Load() == 0 {
		t.Fatal("expected scheduler to run job at least once")
	}
}

func TestSchedulerNilSafe(t *testing.T) {
	var s *Scheduler
	stop := s.Start(context.Background())
	stop()
	s.Every("x", time.Minute, func(_ context.Context) error { return nil })
}
