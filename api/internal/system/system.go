// Package sysinfo 采集宿主机的 CPU / 内存 / 磁盘占用，供管理后台状态面板展示。
//
// 刻意不引入 gopsutil 这类重量级依赖：本项目只需要三个占用率百分比，
// 直接读取 /proc 与 syscall.Statfs 即可，且能覆盖 Linux 容器场景。
// 非 Linux 平台（如本地 macOS 开发）各项返回 0，界面按「暂不可用」处理，
// 不影响其它状态的展示。
package system

// Usage 是单个资源的占用情况。
type Usage struct {
	// Used / Total 为字节数（CPU 时 Total 为 0，只使用 Percent）。
	Used    uint64  `json:"used"`
	Total   uint64  `json:"total"`
	Percent float64 `json:"percent"`
	// Available 表示该指标在当前平台是否可采集。
	Available bool `json:"available"`
}

// Snapshot 是三块资源的占用快照。
type Snapshot struct {
	CPU    Usage `json:"cpu"`
	Memory Usage `json:"memory"`
	Disk   Usage `json:"disk"`
}

// Collect 采集当前进程可见的 CPU / 内存 / 磁盘占用。
// dataDir 用于确定磁盘统计口径（通常是数据目录所在分区）。
func Collect(dataDir string) Snapshot {
	return Snapshot{
		CPU:    cpuUsage(),
		Memory: memoryUsage(),
		Disk:   diskUsage(dataDir),
	}
}

// percent 计算占用百分比，避零除；结果限制在 0~100。
func percent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	p := float64(used) / float64(total) * 100
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}
