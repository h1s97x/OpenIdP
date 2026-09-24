//go:build !linux

package system

// 非 Linux 平台（本地开发常见 macOS / Windows）不采集宿主指标：
// 返回 Available=false，由前端展示为「暂不可用」，避免报错。
func cpuUsage() Usage        { return Usage{} }
func memoryUsage() Usage     { return Usage{} }
func diskUsage(string) Usage { return Usage{} }
