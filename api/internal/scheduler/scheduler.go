// Package task provides a lightweight cron-like scheduler for periodic
// maintenance jobs such as session/token cleanup, audit-log archiving and
// key-rotation reminders. Jobs are registered at startup and run on their
// configured intervals in a single background goroutine.
//
// Usage:
//
//	sched := scheduler.New()
//	sched.Every("session-cleanup", time.Hour, func(ctx) error { ... })
//	sched.Start(ctx)
//	defer sched.Stop()
package scheduler

import (
	"context"
	"log"
	"sync"
	"time"
)

// Job is a single scheduled scheduler. It should return promptly and handle its own
// errors; the scheduler logs failures and continues.
type Job struct {
	Name     string
	Interval time.Duration
	Run      func(ctx context.Context) error
}

// Scheduler manages a set of periodic jobs.
// 每个任务各自维护定时器，到点即执行；任务集合在 Stop 后清空 lastRun，
// 避免长期运行下的残留。
type Scheduler struct {
	mu      sync.Mutex
	jobs    []Job
	lastRun map[string]time.Time
	stop    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

// New creates an empty scheduler.
func New() *Scheduler {
	return &Scheduler{lastRun: make(map[string]time.Time), stop: make(chan struct{})}
}

// Every registers a job that runs every interval. Safe to call before Start.
func (s *Scheduler) Every(name string, interval time.Duration, fn func(ctx context.Context) error) {
	if s == nil || fn == nil || interval <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs = append(s.jobs, Job{Name: name, Interval: interval, Run: fn})
}

// Start launches the scheduler background loop. It runs each job once shortly
// after start, then on its interval. Start is idempotent; it returns a stop
// function that halts the background loop.
func (s *Scheduler) Start(ctx context.Context) (stop func()) {
	if s == nil {
		return func() {}
	}
	s.once.Do(func() {
		s.mu.Lock()
		jobs := append([]Job(nil), s.jobs...)
		s.mu.Unlock()

		// 每个任务一个独立定时器：到点即执行，精度与间隔无关，
		// 也不会因为轮询步长导致实际间隔被拉长。
		for _, j := range jobs {
			s.wg.Add(1)
			go func(j Job) {
				defer s.wg.Done()

				// 启动即运行一轮，尽早完成清理类任务。
				s.markRun(j.Name, time.Now())
				run(j, ctx)

				ticker := time.NewTicker(j.Interval)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-s.stop:
						return
					case now := <-ticker.C:
						s.markRun(j.Name, now)
						run(j, ctx)
					}
				}
			}(j)
		}
	})
	return s.Stop
}

// markRun 记录任务最近一次执行时间。
func (s *Scheduler) markRun(name string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRun[name] = at
}

// Stop halts the scheduler background loop, waits for running jobs to return,
// and drops the recorded run times (避免长期运行后 lastRun 无限驻留)。
func (s *Scheduler) Stop() {
	if s == nil {
		return
	}
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	s.wg.Wait()
	s.mu.Lock()
	s.lastRun = make(map[string]time.Time)
	s.mu.Unlock()
}

func run(j Job, ctx context.Context) {
	if err := j.Run(ctx); err != nil {
		log.Printf("❌ [Task] 任务 %s 执行失败: %v", j.Name, err)
	}
}
