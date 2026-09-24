package geolocation

import "testing"

func TestResolve(t *testing.T) {
	cases := []string{
		"222.137.1.1",     // 河南 郑州 (GeoCN)
		"114.114.114.114", // 江苏 南京 (GeoCN)
		"240e:476::",      // 四川 IPv6 (GeoCN)
		"175.178.88.37",   // ip2region
		"8.8.8.8",         // 境外 → ip2region
		"127.0.0.1",       // 本机
		"10.0.0.1",        // 内网
	}
	for _, ip := range cases {
		r, ok := ResolveDetailed(ip)
		if ok {
			t.Logf("%s -> %s %+v", ip, r.Region, r)
		} else {
			t.Logf("%s -> 未知", ip)
		}
	}
}
