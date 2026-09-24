//go:build linux

package system

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// cpuSampler 记录上一次 /proc/stat 的采样值：CPU 占用是区间量，
// 需要两次采样求差，单次读数只能得到累计值。
type cpuSampler struct {
	mu        sync.Mutex
	idle      uint64
	total     uint64
	sampledAt time.Time
}

var sampler cpuSampler

// cpuUsage 读取 /proc/stat 的第一行（整体 CPU 时间），与上次采样做差得到占用率。
// 首次调用没有基准，返回 0 并记录基准；下一次调用起结果有效。
func cpuUsage() Usage {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return Usage{}
	}
	line := ""
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "cpu ") {
			line = l
			break
		}
	}
	if line == "" {
		return Usage{}
	}
	fields := strings.Fields(line)[1:]
	var total, idle uint64
	for i, f := range fields {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			continue
		}
		total += v
		// 第 3、4 个字段（索引 3、4）分别是 idle 与 iowait。
		if i == 3 || i == 4 {
			idle += v
		}
	}

	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	prevIdle, prevTotal := sampler.idle, sampler.total
	sampler.idle, sampler.total = idle, total
	sampler.sampledAt = time.Now()

	if prevTotal == 0 || total <= prevTotal {
		return Usage{Available: true}
	}
	dTotal := total - prevTotal
	dIdle := idle - prevIdle
	used := dTotal - dIdle
	return Usage{
		Used:      used,
		Total:     dTotal,
		Percent:   percent(used, dTotal),
		Available: true,
	}
}

// memoryUsage 读取 /proc/meminfo 计算内存占用（MemTotal - MemAvailable）。
func memoryUsage() Usage {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return Usage{}
	}
	var totalKB, availKB uint64
	for _, l := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(l)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totalKB = v
		case "MemAvailable:":
			availKB = v
		}
	}
	if totalKB == 0 {
		return Usage{}
	}
	total := totalKB * 1024
	avail := availKB * 1024
	used := uint64(0)
	if total > avail {
		used = total - avail
	}
	return Usage{Used: used, Total: total, Percent: percent(used, total), Available: true}
}

// diskUsage 用 statfs 读取数据目录所在分区的容量与剩余空间。
func diskUsage(path string) Usage {
	if path == "" {
		path = "/"
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Usage{}
	}
	bsize := uint64(st.Bsize)
	total := st.Blocks * bsize
	free := st.Bavail * bsize
	used := uint64(0)
	if total > free {
		used = total - free
	}
	return Usage{Used: used, Total: total, Percent: percent(used, total), Available: true}
}
