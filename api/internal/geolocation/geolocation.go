// Package geo resolves IP addresses to human-readable regions.
//
// Resolution chain (first hit wins):
//  1. GeoCN.mmdb — 中国大陆高精度 IPv4/IPv6 离线库（ljxi/GeoCN，部分 IP 精确到区县）
//  2. ip2region.xdb — 通用离线库兜底（非中国大陆 / GeoCN 未命中）
//  3. 外部 API 源（可选，通过 OPENIDP_GEO_API_SOURCES 启用）—— 支持 ip-api.com / ipinfo.io /
//     ipapi.co / ip.sb 等公共接口，带内存缓存与超时保护
package geolocation

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/oschwald/maxminddb-golang"

	"github.com/h1s97x/openidp/api/internal/config"
)

//go:embed GeoCN.mmdb
var geoCNData embed.FS

//go:embed ip2region.xdb
var xdbData embed.FS

//go:embed full.txt
var divisionFullTxt string

// Result is the detailed result of an IP lookup.
type Result struct {
	IP       string `json:"ip"`
	Region   string `json:"region"` // 展示字符串：中国 · 河南 · 郑州市 · 联通
	Country  string `json:"country,omitempty"`
	Province string `json:"province,omitempty"`
	City     string `json:"city,omitempty"`
	ISP      string `json:"isp,omitempty"`
}

var (
	// cnReader / xdbS 用原子指针持有：管理员可以在后台改自定义库路径并触发重载，
	// 而并发请求正在解析 IP。普通指针字段会构成数据竞争。
	cnReader atomic.Pointer[maxminddb.Reader]
	xdbS     atomic.Pointer[xdb.Searcher]
	// loaded 标记内置库是否已尝试装载（外部库装载成功时无需再读内置库）。
	cnOnce  sync.Once
	xdbOnce sync.Once
	// hadExternal 标记当前是否已使用外部库装载成功。
	cnErr  atomic.Value // string
	xdbErr atomic.Value // string

	divisionFull map[int]string
	divOnce      sync.Once

	apiClient *http.Client
	// apiCache: ip -> cachedEntry。由 trimAPICache 做惰性清理（按 trimAPICacheBatch
	// 限量删除已过期条目），避免该 sync.Map 无界增长导致内存泄漏。
	apiCache sync.Map
	cacheTTL = 24 * time.Hour
)

type cachedEntry struct {
	res *Result
	at  time.Time
}

func init() {
	apiClient = &http.Client{Timeout: 4 * time.Second}
	if ttl := config.Getenv("GEO_API_CACHE_TTL"); ttl != "" {
		if d, err := time.ParseDuration(ttl); err == nil && d > 0 {
			cacheTTL = d
		}
	}
}

// configureMu 串行化库的装载，并记住当前生效的自定义路径：
// 路径未变时为无操作，因此可以在每次保存设置时安全调用。
var (
	configureMu  sync.Mutex
	lastCNPath   string
	lastXDBPath  string
	configuredDB bool
)

// Configure 按给定的自定义库路径装载解析库（管理后台「IP 归属地」可配）。
//
// 内置 mmdb/xdb 随二进制嵌入；管理员填了自定义库路径却完全不生效，
// 会让这一项配置形同虚设。这里按路径装载外部库，读取或解析失败都回落到内置库——
// 归属地是审计信息而非鉴权依据，宁可展示得差一点，也不能因此让解析整体不可用。
//
// 并发安全：装载结果通过原子指针发布，读取侧不做任何同步等待。
func Configure(geoCNDBPath, ip2RegionDBPath string) {
	cnPath := strings.TrimSpace(geoCNDBPath)
	xdbPath := strings.TrimSpace(ip2RegionDBPath)

	configureMu.Lock()
	defer configureMu.Unlock()
	if configuredDB && cnPath == lastCNPath && xdbPath == lastXDBPath {
		return
	}
	configuredDB = true
	lastCNPath = cnPath
	lastXDBPath = xdbPath

	// 外部库装载成功才替换当前生效的库；失败（或路径已清空）时回落到内置库。
	// 先读内置库、再按需覆盖，避免出现「两个库都不可用」的中间态。
	if cnPath != "" {
		if buf, err := os.ReadFile(cnPath); err == nil {
			if r, err := maxminddb.FromBytes(buf); err == nil {
				cnReader.Store(r)
				cnErr.Store("")
			} else {
				fmt.Fprintf(os.Stderr, "⚠️ [Geo] 自定义 GeoCN 库解析失败（%s），回落到内置库: %v\n", cnPath, err)
				loadBuiltinGeoCN()
			}
		} else {
			fmt.Fprintf(os.Stderr, "⚠️ [Geo] 自定义 GeoCN 库不可读（%s），回落到内置库: %v\n", cnPath, err)
			loadBuiltinGeoCN()
		}
	} else {
		loadBuiltinGeoCN()
	}

	if xdbPath != "" {
		if buf, err := os.ReadFile(xdbPath); err == nil {
			if searcher, err := xdb.NewWithBuffer(xdb.IPv4, buf); err == nil {
				xdbS.Store(searcher)
				xdbErr.Store("")
			} else {
				fmt.Fprintf(os.Stderr, "⚠️ [Geo] 自定义 ip2region 库解析失败（%s），回落到内置库: %v\n", xdbPath, err)
				loadBuiltinXDB()
			}
		} else {
			fmt.Fprintf(os.Stderr, "⚠️ [Geo] 自定义 ip2region 库不可读（%s），回落到内置库: %v\n", xdbPath, err)
			loadBuiltinXDB()
		}
	} else {
		loadBuiltinXDB()
	}
}

// loadBuiltinGeoCN 装载随二进制嵌入的 GeoCN 库（幂等，可重复调用）。
func loadBuiltinGeoCN() {
	buf, err := geoCNData.ReadFile("GeoCN.mmdb")
	if err != nil {
		cnErr.Store(fmt.Sprintf("read GeoCN.mmdb: %v", err))
		return
	}
	r, err := maxminddb.FromBytes(buf)
	if err != nil {
		cnErr.Store(fmt.Sprintf("open GeoCN.mmdb: %v", err))
		return
	}
	cnErr.Store("")
	cnReader.Store(r)
}

// loadBuiltinXDB 装载随二进制嵌入的 ip2region 库（幂等，可重复调用）。
func loadBuiltinXDB() {
	buf, err := xdbData.ReadFile("ip2region.xdb")
	if err != nil {
		xdbErr.Store(fmt.Sprintf("read ip2region.xdb: %v", err))
		return
	}
	searcher, err := xdb.NewWithBuffer(xdb.IPv4, buf)
	if err != nil {
		xdbErr.Store(err.Error())
		return
	}
	xdbErr.Store("")
	xdbS.Store(searcher)
}

// ensureDB 懒加载 GeoCN.mmdb 与 ip2region.xdb。两个库独立初始化，互不影响：
// GeoCN 失败时 ip2region 仍可正常工作（兜底），反之亦然，避免“连带失效”。
//
// 外部库已由 Configure 装载时不重复读盘（sync.Once 保证只尝试一次内置装载）。
func ensureDB() error {
	ensureGeoCN()
	ensureXDB()
	if errOf(cnErr) != "" && errOf(xdbErr) != "" {
		return fmt.Errorf("%s", errOf(cnErr))
	}
	return nil
}

// errOf 读取 atomic.Value 里保存的错误字符串（未写入时为空）。
func errOf(v atomic.Value) string {
	if s, ok := v.Load().(string); ok {
		return s
	}
	return ""
}

func ensureGeoCN() {
	cnOnce.Do(func() {
		// 已由 Configure 用外部库装载成功：不覆盖。
		if cnReader.Load() != nil {
			return
		}
		loadBuiltinGeoCN()
	})
}

func ensureXDB() {
	xdbOnce.Do(func() {
		// 已由 Configure 用外部库装载成功：不覆盖。
		if xdbS.Load() != nil {
			return
		}
		loadBuiltinXDB()
	})
}

// ensureDivisions loads the embedded division code tables.
func ensureDivisions() {
	divOnce.Do(func() {
		divisionFull = loadDivisionMap(divisionFullTxt, "\t")
	})
}

func loadDivisionMap(content, sep string) map[int]string {
	m := make(map[int]string)
	sc := strings.NewReader(content)
	for {
		line, err := readLine(sc)
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, sep, 2)
		if len(parts) != 2 {
			continue
		}
		code, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			continue
		}
		m[code] = strings.TrimSpace(parts[1])
	}
	return m
}

// readLine reads one line from a string reader without adding dependencies.
func readLine(r *strings.Reader) (string, error) {
	var b strings.Builder
	for {
		ch, _, err := r.ReadRune()
		if err != nil {
			if b.Len() > 0 {
				return b.String(), nil
			}
			return "", err
		}
		if ch == '\n' {
			return b.String(), nil
		}
		b.WriteRune(ch)
	}
}

// Resolve returns a display string like "中国 · 河南 · 郑州市 · 联通".
func Resolve(ip string) string {
	if r, ok := ResolveDetailed(ip); ok {
		return r.Region
	}
	return "未知区域"
}

// ResolveDetailed resolves an IP with the full detail chain.
func ResolveDetailed(ip string) (*Result, bool) {
	ip = normalizeIP(ip)
	if ip == "" {
		return nil, false
	}
	if isPrivate(ip) {
		return &Result{IP: ip, Region: "本机 / 内网"}, true
	}
	if net.ParseIP(ip) == nil {
		return nil, false
	}
	if err := ensureDB(); err != nil {
		// 两个离线库均不可用时才退回外部 API（此时 r 必为 nil 或不可用）。
		if r := lookupIP2Region(ip); r != nil {
			return r, true
		}
		if r := lookupGeoCN(ip); r != nil {
			return r, true
		}
		return resolveFromAPI(ip)
	}

	// 1. GeoCN mmdb（优先，仅覆盖中国大陆段）
	if r := lookupGeoCN(ip); r != nil {
		return r, true
	}
	// 2. ip2region 兜底
	if r := lookupIP2Region(ip); r != nil {
		return r, true
	}
	// 3. 外部 API 源
	return resolveFromAPI(ip)
}

// normalizeIP strips port / brackets and trims whitespace.
func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if i := strings.LastIndex(ip, ":"); i > 0 && strings.Count(ip, ":") == 1 {
		host := ip[:i]
		if net.ParseIP(host) != nil {
			ip = host
		}
	}
	return strings.Trim(ip, "[]")
}

func isPrivate(ip string) bool {
	if ip == "::1" {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() {
		return true
	}
	if v4 := parsed.To4(); v4 != nil {
		if v4[0] == 10 || v4[0] == 127 || v4[0] == 0 {
			return true
		}
		if v4[0] == 192 && v4[1] == 168 {
			return true
		}
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return true
		}
	}
	return false
}

// ---- GeoCN mmdb ----

type geoCNRecord struct {
	DivisionCode uint32 `maxminddb:"division_code"`
	ISP          string `maxminddb:"isp"`
	Type         string `maxminddb:"type"`
}

func lookupGeoCN(ip string) *Result {
	reader := cnReader.Load()
	if reader == nil {
		return nil
	}
	var rec geoCNRecord
	if err := reader.Lookup(net.ParseIP(ip), &rec); err != nil || rec.DivisionCode == 0 {
		return nil
	}
	ensureDivisions()
	province, city := resolveDivision(rec.DivisionCode)
	isp := rec.ISP
	if isp == "" {
		isp = "未知运营商"
	}
	r := &Result{
		IP:       ip,
		Country:  "中国",
		Province: province,
		City:     city,
		ISP:      isp,
	}
	if rec.Type != "" {
		r.ISP = isp + " " + rec.Type
	}
	// 只展示到城市粒度（不拼接区县），国家名已给出时也不再补 "CN"。
	r.Region = joinRegion("中国", province, city, r.ISP, "CN")
	return r
}

// resolveDivision maps a 行政区划代码 to 省/市 names.
// 区县不再用于展示（避免「… · 兰州市 · 榆中县 · …」这类过长结果）。
func resolveDivision(code uint32) (province, city string) {
	c := int(code)
	if c == 0 {
		return
	}
	provinceCode := (c / 10000) * 10000
	cityCode := (c / 100) * 100

	if v, ok := divisionFull[provinceCode]; ok {
		province = v
	}
	if cityCode != provinceCode {
		if v, ok := divisionFull[cityCode]; ok {
			city = v
		}
	}
	// 直辖市：省=市 时去重
	if city != "" && city == province {
		city = ""
	}
	return
}

// ---- ip2region ----

func lookupIP2Region(ip string) *Result {
	searcher := xdbS.Load()
	if searcher == nil {
		return nil
	}
	raw, err := searcher.Search(ip)
	if err != nil || raw == "" {
		return nil
	}
	return formatIP2Region(ip, raw)
}

func formatIP2Region(ip, raw string) *Result {
	parts := strings.Split(raw, "|")
	country := strings.TrimSpace(part(parts, 0))
	province := strings.TrimSpace(part(parts, 1))
	city := strings.TrimSpace(part(parts, 2))
	isp := strings.TrimSpace(part(parts, 3))
	countryCode := strings.TrimSpace(part(parts, 4))

	if country == "" || country == "0" || country == "内网IP" {
		return &Result{IP: ip, Region: "内网 / 未知区域"}
	}

	r := &Result{
		IP:       ip,
		Country:  country,
		Province: province,
		City:     city,
		ISP:      ispLabel(isp),
	}
	r.Region = joinRegion(country, province, city, r.ISP, countryCode)
	return r
}

func part(parts []string, i int) string {
	if i < len(parts) {
		return parts[i]
	}
	return ""
}

// ispLabel maps ip2region ISP names to friendly labels.
func ispLabel(isp string) string {
	switch isp {
	case "电信", "联通", "移动", "铁通", "教育网", "鹏博士":
		return isp
	}
	low := strings.ToLower(isp)
	switch {
	case strings.Contains(low, "tencent") || strings.Contains(low, "腾讯"):
		return "腾讯"
	case strings.Contains(low, "aliyun") || strings.Contains(low, "阿里"):
		return "阿里云"
	case strings.Contains(low, "amazon") || strings.Contains(low, "aws"):
		return "AWS"
	case strings.Contains(low, "microsoft") || strings.Contains(low, "azure"):
		return "微软"
	case strings.Contains(low, "google"):
		return "谷歌"
	}
	if isp == "" || isp == "0" {
		return ""
	}
	return isp
}

// joinRegion 组装归属地展示字符串：国家 · 省/州 · 城市 · 运营商（· 国家代码）。
//
// 只保留到「城市」粒度，不再拼接区县；国家代码仅在与国家名不构成重复时展示，
// 避免出现「中国 · 甘肃省 · 兰州市 · 榆中县 · 联通 · CN」这类冗长结果。
func joinRegion(country, province, city, isp, countryCode string) string {
	clean := func(v string) string {
		v = strings.TrimSpace(v)
		if v == "0" {
			return ""
		}
		return v
	}
	country = clean(country)
	province = clean(province)
	city = clean(city)
	isp = clean(isp)
	countryCode = clean(countryCode)

	segs := make([]string, 0, 5)
	if country != "" {
		segs = append(segs, country)
	}
	if province != "" && province != country {
		segs = append(segs, province)
	}
	if city != "" && city != province {
		segs = append(segs, city)
	}
	if isp != "" {
		segs = append(segs, isp)
	}
	// 国家名已用中文标出时，再补一个 "CN" 属于冗余信息。
	if countryCode != "" && countryCode != "CN" {
		segs = append(segs, countryCode)
	}
	return strings.Join(segs, " · ")
}

// ---- External API sources ----

// apiSource is a pluggable external geo source.
type apiSource struct {
	name   string
	lookup func(ctx context.Context, client *http.Client, ip string) (*Result, error)
}

// sources is the registry of built-in external API sources.
var sources = []apiSource{
	{name: "ip-api.com", lookup: lookupIPAPI},
	{name: "ipinfo.io", lookup: lookupIPInfo},
	{name: "ipapi.co", lookup: lookupIPAPICo},
	{name: "ip.sb", lookup: lookupIPSB},
}

// enabledAPISources returns the enabled source names from OPENIDP_GEO_API_SOURCES.
func enabledAPISources() []string {
	raw := config.Getenv("GEO_API_SOURCES")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// trimAPICache 控制 GeoIP 结果缓存的无界增长：
// 每次写入时顺带清理"当前遍历到的"过期条目，直到累计清理到阈值就停止，
// 避免全表扫描带来的写入放大。
func trimAPICache() {
	var expired int
	now := time.Now()
	apiCache.Range(func(k, v any) bool {
		if ce, ok := v.(cachedEntry); ok && now.Sub(ce.at) >= cacheTTL {
			apiCache.Delete(k)
			expired++
		}
		// 累计清理到上限就提前结束遍历，避免每次写入都全表扫描。
		return expired < trimAPICacheBatch
	})
}

// trimAPICacheBatch 是单次清理最多遍历并删除的条目数。
const trimAPICacheBatch = 256

func resolveFromAPI(ip string) (*Result, bool) {
	enabled := enabledAPISources()
	if len(enabled) == 0 {
		return nil, false
	}
	if v, ok := apiCache.Load(ip); ok {
		ce := v.(cachedEntry)
		if time.Since(ce.at) < cacheTTL {
			return ce.res, true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	for _, name := range enabled {
		for _, src := range sources {
			if src.name != name {
				continue
			}
			res, err := src.lookup(ctx, apiClient, ip)
			if err != nil || res == nil {
				continue
			}
			trimAPICache()
			apiCache.Store(ip, cachedEntry{res: res, at: time.Now()})
			return res, true
		}
	}
	return nil, false
}

// lookupIPAPI uses ip-api.com (free, 45 req/min, supports zh-CN).
func lookupIPAPI(ctx context.Context, client *http.Client, ip string) (*Result, error) {
	url := "https://ip-api.com/json/" + ip + "?lang=zh-CN&fields=status,country,countryCode,regionName,city,isp,org,as,query"
	var d struct {
		Status      string `json:"status"`
		Query       string `json:"query"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		RegionName  string `json:"regionName"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
	}
	if err := getJSON(ctx, client, url, &d); err != nil {
		return nil, err
	}
	if d.Status != "success" {
		return nil, fmt.Errorf("ip-api.com failed")
	}
	r := &Result{
		IP:       d.Query,
		Country:  d.Country,
		Province: d.RegionName,
		City:     d.City,
		ISP:      d.ISP,
	}
	r.Region = joinRegion(d.Country, d.RegionName, d.City, d.ISP, d.CountryCode)
	return r, nil
}

// lookupIPInfo uses ipinfo.io (free tier).
func lookupIPInfo(ctx context.Context, client *http.Client, ip string) (*Result, error) {
	url := "https://ipinfo.io/" + ip + "/json"
	var d struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		Region  string `json:"region"`
		City    string `json:"city"`
		Org     string `json:"org"`
	}
	if err := getJSON(ctx, client, url, &d); err != nil {
		return nil, err
	}
	if d.Country == "" {
		return nil, fmt.Errorf("ipinfo.io empty")
	}
	r := &Result{
		IP:       d.IP,
		Province: d.Region,
		City:     d.City,
	}
	r.Region = joinRegion(d.Country, d.Region, d.City, d.Org, "")
	return r, nil
}

// lookupIPAPICo uses ipapi.co (free tier, limited).
func lookupIPAPICo(ctx context.Context, client *http.Client, ip string) (*Result, error) {
	url := "https://ipapi.co/" + ip + "/json/"
	var d struct {
		IP          string `json:"ip"`
		CountryName string `json:"country_name"`
		Country     string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Org         string `json:"org"`
	}
	if err := getJSON(ctx, client, url, &d); err != nil {
		return nil, err
	}
	if d.Country == "" {
		return nil, fmt.Errorf("ipapi.co empty")
	}
	r := &Result{
		IP:       d.IP,
		Country:  d.CountryName,
		Province: d.Region,
		City:     d.City,
	}
	r.Region = joinRegion(d.CountryName, d.Region, d.City, d.Org, d.Country)
	return r, nil
}

// lookupIPSB uses ip.sb.
func lookupIPSB(ctx context.Context, client *http.Client, ip string) (*Result, error) {
	url := "https://api.ip.sb/geoip/" + ip
	var d struct {
		IP           string `json:"ip"`
		Country      string `json:"country"`
		CountryCode  string `json:"country_code"`
		Region       string `json:"region"`
		City         string `json:"city"`
		ISP          string `json:"isp"`
		Organization string `json:"organization"`
	}
	if err := getJSON(ctx, client, url, &d); err != nil {
		return nil, err
	}
	if d.Country == "" {
		return nil, fmt.Errorf("ip.sb empty")
	}
	r := &Result{
		IP:       d.IP,
		Country:  d.Country,
		Province: d.Region,
		City:     d.City,
		ISP:      d.ISP,
	}
	r.Region = joinRegion(d.Country, d.Region, d.City, d.ISP, d.CountryCode)
	return r, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "openidp/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}
