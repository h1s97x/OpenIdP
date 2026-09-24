package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// 本文件解决「反代 / CDN 之后如何拿到真实客户端 IP」的问题。
//
// 典型的 OpenIdP 生产链路是：
//
//	用户 → CDN（EdgeOne / ESA / Cloudflare）→ 反向代理（宝塔 Nginx）→ OpenIdP
//
// 这条链路上有三个容易出错的地方，逐个处理：
//
//  1. 取哪一个头。X-Forwarded-For 是「追加」语义，客户端可以在最左侧塞入
//     任意值，因此固定取第一个元素是可以伪造的。CDN 提供的专用头
//     （CF-Connecting-IP / EO-Client-IP / ali-real-client-ip）是单值、由边缘
//     节点写入，客户端无法追加，优先级应当最高。
//  2. 是否该相信这些头。只有直接对端是可信代理（默认回环 + 内网网段，可用
//     TrustedProxies 扩充）时才采信；否则攻击者只要能绕过 Nginx 直连到
//     服务端口，就能任意伪造 IP，进而使限流、审计、归属地全部失效。
//  3. XFF 从哪一端数。应当从右往左跳过可信跳与内网脏数据，因为客户端只能
//     「前插」条目，无法「后插」。任何情况下都不取最左值。

// ClientIPConfig 描述一次请求解析客户端 IP 时可用的配置。
type ClientIPConfig struct {
	// TrustProxy 是否解析反向代理 / CDN 传递的转发头。
	// 开启时也只信任可信网段内的对端（见 TrustedProxies）；
	// 关闭时一律使用 TCP 对端地址，适用于直接公网暴露的部署。
	TrustProxy bool

	// Header 优先读取的客户端 IP 头，例如 CF-Connecting-IP、
	// EO-Client-IP、ali-real-client-ip。留空时仍会按固定顺序
	// 嗅探常见 CDN 专用头，再进入 XFF 回退。
	Header string

	// TrustedProxies 是额外可信的代理网段（CIDR 或裸 IP），
	// 会与默认的「回环 + RFC1918 私网 + fc00::/7」合并。
	// 只有 TCP 对端落在可信网段内才会采信转发头。
	TrustedProxies []string
}

// defaultTrustedProxyCIDRs 是未显式配置 TrustedProxies 时默认信任的对端网段：
// 回环 + RFC1918 私网 + IPv6 ULA。常见的「Nginx 与应用同机 / 内网」部署，
// 对端必然落在其中，因此无需任何配置即可安全地采信转发头。
var defaultTrustedProxyCIDRs = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"fc00::/7",
}

// nonRoutableCIDRs 是解析 XFF 时视为「不可能是客户端」的内网地址：
// 在默认可信网段之外，还包括运营商级 NAT（CGNAT）与链路本地地址，
// 用于跳过反代误写入头部的内网脏数据（如 X-Real-IP 被覆盖成 127.0.0.1）。
var nonRoutableCIDRs = append(append([]string{}, defaultTrustedProxyCIDRs...),
	"100.64.0.0/10", "fe80::/10")

var (
	defaultTrustedNets = parseProxies(defaultTrustedProxyCIDRs)
	nonRoutableNets    = parseProxies(nonRoutableCIDRs)
)

// wellKnownIPHeaders 是常见 CDN 写入的专用真实 IP 头。
// 这些头均为单值、由边缘节点写入，客户端无法追加，可信度高于 XFF。
var wellKnownIPHeaders = []string{
	"EO-Client-IP",       // 腾讯云 EdgeOne（控制台开启「客户端 IP 头部」后携带）
	"EO-Connecting-IP",   // 腾讯云 EdgeOne（默认携带）
	"CF-Connecting-IP",   // Cloudflare（默认携带）
	"ali-real-client-ip", // 阿里云 ESA（开启托管转换后携带）
	"True-Client-IP",     // 部分企业版 CDN
}

// ResolveClientIP 推导请求的真实客户端 IP。
//
// 采信转发头时的取值顺序：
//  1. 专用真实 IP 头（Header），缺省时依次嗅探常见 CDN 专用头；
//  2. X-Forwarded-For，从右往左跳过可信跳与内网脏数据；
//  3. TCP 对端地址。
func ResolveClientIP(r *http.Request, cfg ClientIPConfig) string {
	peer := normaliseIP(r.RemoteAddr)

	if !cfg.TrustProxy {
		return peer
	}
	// 可信网段 = 默认内网网段 + 配置的额外网段。
	nets := mergeTrustedNets(cfg.TrustedProxies)
	// 对端不在可信网段内时，转发头一律不采信。
	// 否则绕过反代直连服务端口的人可以任意伪造来源 IP，
	// 使登录限流、审计记录与归属地全部失真。
	if !inNets(nets, peer) {
		return peer
	}

	for _, name := range headerCandidates(cfg.Header) {
		if ip := firstIP(r.Header.Get(name)); ip != "" {
			return ip
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := clientFromXFF(xff, nets); ip != "" {
			return ip
		}
	}
	return peer
}

// TrustedPeer 报告请求的 TCP 对端是否落在可信代理网段内。
//
// 这是「是否采信转发头」的前置判定：只有来自可信代理（默认回环 + 内网网段，
// 可用 TrustedProxies 扩充）的对端，其 X-Forwarded-* 头才可信。直接公网暴露时
// 对端是公网地址，返回 false，转发头一律不采信。
//
// 与 ResolveClientIP 内部使用的是同一套网段判定，避免各处重复实现导致判定漂移。
func TrustedPeer(r *http.Request, extra []string) bool {
	peer := normaliseIP(r.RemoteAddr)
	if peer == "" {
		return false
	}
	return inNets(mergeTrustedNets(extra), peer)
}

// mergeTrustedNets 合并默认可信网段与配置的额外网段，结果按配置键记忆化。
func mergeTrustedNets(extra []string) []*net.IPNet {
	if len(extra) == 0 {
		return defaultTrustedNets
	}
	key := "default|" + strings.Join(extra, ",")
	if v, ok := proxyCache.Load(key); ok {
		return v.([]*net.IPNet)
	}
	merged := append(append([]*net.IPNet{}, defaultTrustedNets...), parseProxies(extra)...)
	if proxyCacheSize() >= maxProxyCacheEntries {
		proxyCache.Clear()
	}
	proxyCache.Store(key, merged)
	return merged
}

// headerCandidates 生成专用头的读取顺序：显式配置的头最优先，
// 其后按固定顺序嗅探常见 CDN 专用头（跳过重复项）。
func headerCandidates(cfgHeader string) []string {
	names := make([]string, 0, len(wellKnownIPHeaders)+1)
	if cfgHeader != "" {
		names = append(names, cfgHeader)
	}
	for _, name := range wellKnownIPHeaders {
		if name == cfgHeader {
			continue
		}
		names = append(names, name)
	}
	return names
}

// normaliseIP 去掉地址中可选的端口，返回可直接交给 net.ParseIP 的 IP 串。
//
// 覆盖实际会遇到的几种形式：
//
//	1.2.3.4:56789 → 1.2.3.4
//	1.2.3.4       → 1.2.3.4
//	[::1]:56789   → ::1
//	[::1]         → ::1
//	::1           → ::1
//
// 旧实现按最后一个冒号截断，会把 "[::1]:6099" 截成 "[::1]"（保留方括号），
// 导致所有对 IPv6 对端调用 net.ParseIP 都失败，进而让
// SETUP_ALLOW_REMOTE=false 的本机判断与归属地解析在 IPv6 下失效。
func normaliseIP(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	// 没有端口：去掉 IPv6 字面量可能带有的方括号。
	return strings.Trim(addr, "[]")
}

// firstIP 返回逗号分隔头部值中第一个合法的 IP。
// 非法条目会被跳过，避免 "not-an-ip" 之类的值被当成客户端地址记录进审计。
func firstIP(v string) string {
	for _, part := range strings.Split(v, ",") {
		ip := normaliseIP(part)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// clientFromXFF 从 X-Forwarded-For 中挑出客户端地址。
//
// 一律从右往左遍历：客户端只能在最左侧前插伪造条目，右侧由可信代理逐跳追加，
// 这是唯一能抵抗伪造的方向。第一轮跳过非法值、可信网段与内网地址（反代把
// 内网地址写进 XFF 的脏数据），取第一个剩余的公网地址；全部条目均为内网时
// （纯内网部署），退回最右侧的合法条目。
func clientFromXFF(xff string, nets []*net.IPNet) string {
	parts := strings.Split(xff, ",")

	for i := len(parts) - 1; i >= 0; i-- {
		ip := normaliseIP(parts[i])
		if net.ParseIP(ip) == nil || inNets(nets, ip) || inNets(nonRoutableNets, ip) {
			continue
		}
		return ip
	}
	// 纯内网部署：所有条目都是内网地址。初始客户端在最左，
	// 右侧为内网代理逐跳追加，因此取最左侧的合法条目。
	for i := 0; i < len(parts); i++ {
		ip := normaliseIP(parts[i])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// inNets 判断地址是否落在任一网段内。
// net.IPNet.Contains 会自动处理 IPv4-in-IPv6 映射（::ffff:127.0.0.1）。
func inNets(nets []*net.IPNet, addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseProxies 把配置项解析成网段列表，非法条目静默忽略。
func parseProxies(list []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(list))
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// 允许写裸 IP，等价于单主机网段，配置时不必手写 /32、/128。
		if !strings.Contains(entry, "/") {
			if ip := net.ParseIP(entry); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				entry = entry + "/" + strconv.Itoa(bits)
			}
		}
		if _, n, err := net.ParseCIDR(entry); err == nil && n != nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// ResolveClientIP 每个请求都会调用，而网段解析只在管理员改动配置后才需要重做，
// 因此由 mergeTrustedNets 按配置值做一层记忆化，避免每请求重复解析。
var proxyCache sync.Map // string → []*net.IPNet

// maxProxyCacheEntries 是记忆化表的上限。键空间只来自管理员的不同配置值，
// 正常只有个位数；加上限只是防止异常调用把它无限撑大。
const maxProxyCacheEntries = 256

func proxyCacheSize() int {
	n := 0
	proxyCache.Range(func(_, _ any) bool { n++; return true })
	return n
}
