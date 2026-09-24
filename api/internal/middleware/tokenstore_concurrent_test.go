package middleware

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestTokenStoreConcurrent stresses the store with concurrent Set/Check/Take/
// Delete/Has from many goroutines. Run with -race to detect data races.
func TestTokenStoreConcurrent(t *testing.T) {
	ts := NewTokenStore(newTestCache(), 5*time.Minute)
	var wg sync.WaitGroup

	// writers
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ts.Set(fmt.Sprintf("tok-%d-%d", gid, i), int64(gid), fmt.Sprintf("sess-%d", gid))
			}
		}(g)
	}
	// readers / takers
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				key := fmt.Sprintf("tok-%d-%d", gid, i)
				_ = ts.Check(key, fmt.Sprintf("sess-%d", gid))
				_ = ts.Has(key)
				if i%3 == 0 {
					ts.Take(key)
				}
			}
		}(g)
	}
	wg.Wait()
}
