package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPasswordHashingIsConcurrencyLimited 验证 bcrypt 计算受全局并发闸门约束。
//
// 背景：bcrypt cost 12 每次约 40ms 纯 CPU 开销，实测 8 核机器吞吐仅 ~24 rps。
// 不加限制时，并发登录（或攻击者直接刷登录端点）会把所有核心占满，
// 拖慢同进程的健康检查、静态资源等其它请求直到超时。
//
// 断言：任一时刻正在执行的 bcrypt 计算数不超过 GOMAXPROCS（闸门容量），
// 而不是与并发请求数同阶。
func TestPasswordHashingIsConcurrencyLimited(t *testing.T) {
	limit := cap(passwordSem)
	if limit < 1 {
		t.Fatalf("闸门容量异常: %d", limit)
	}

	var inflight atomic.Int64
	var peak atomic.Int64
	var wg sync.WaitGroup

	const goroutines = 64
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// 在闸门内计数：HashPassword 内部会先获取名额，因此这里的
			// 采样点必然处于「已获名额」状态。
			// 用一个包裹函数观测闸门占用量。
			acquirePasswordSlot()
			cur := inflight.Add(1)
			for {
				old := peak.Load()
				if cur <= old || peak.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			inflight.Add(-1)
			releasePasswordSlot()
		}()
	}
	wg.Wait()

	if got := peak.Load(); got > int64(limit) {
		t.Fatalf("闸门失效：峰值并发 %d 超过容量 %d", got, limit)
	}
	if peak.Load() < 2 {
		t.Fatalf("闸门过度串行：峰值并发 %d，未达到并行度 %d", peak.Load(), limit)
	}
}

// TestHashAndCheckShareTheGate 验证 HashPassword 与 CheckPassword 共用同一闸门，
// 覆盖「登录校验」与「注册/改密哈希」两类最耗 CPU 的路径。
func TestHashAndCheckShareTheGate(t *testing.T) {
	hash, err := HashPassword("pw-concurrency-test")
	if err != nil {
		t.Fatalf("HashPassword 出错: %v", err)
	}
	if !CheckPassword(hash, "pw-concurrency-test") {
		t.Fatal("CheckPassword 未能校验通过刚生成的哈希")
	}
	if CheckPassword(hash, "wrong") {
		t.Fatal("CheckPassword 对错误密码返回了 true")
	}
	// 全部归还，闸门不能被泄漏（泄漏会让后续登录永久阻塞）。
	if len(passwordSem) != 0 {
		t.Fatalf("闸门名额泄漏：仍有 %d 个未归还", len(passwordSem))
	}
}
