package config

import (
	"os"
	"testing"
)

func TestRedisEnvParsing(t *testing.T) {
	t.Setenv("OPENIDP_REDIS_ADDR", "myredis:6379")
	t.Setenv("OPENIDP_REDIS_DB", "3")
	t.Setenv("OPENIDP_REDIS_PASSWORD", "s3cret")
	c := FromEnv()
	if c.RedisAddr != "myredis:6379" {
		t.Fatalf("RedisAddr = %q; want myredis:6379", c.RedisAddr)
	}
	if c.RedisDB != 3 {
		t.Fatalf("RedisDB = %d; want 3", c.RedisDB)
	}
	if c.RedisPassword != "s3cret" {
		t.Fatalf("RedisPassword = %q; want s3cret", c.RedisPassword)
	}
}

func TestDevFrontendURLParsing(t *testing.T) {
	t.Setenv("OPENIDP_DEV_FRONTEND_URL", "http://localhost:5173")
	c := FromEnv()
	if c.DevFrontendURL != "http://localhost:5173" {
		t.Fatalf("DevFrontendURL = %q; want http://localhost:5173", c.DevFrontendURL)
	}
}

func TestDevFrontendURLDefaults(t *testing.T) {
	// 未配置时应为空（生产内嵌模式，不启用代理）
	os.Unsetenv("OPENIDP_DEV_FRONTEND_URL")
	c := FromEnv()
	if c.DevFrontendURL != "" {
		t.Fatalf("DevFrontendURL default = %q; want empty", c.DevFrontendURL)
	}
}

func TestRedisEnvDefaults(t *testing.T) {
	// 未配置时应为空地址（触发内存缓存降级）与默认 DB=0。
	for _, k := range []string{"OPENIDP_REDIS_ADDR", "OPENIDP_REDIS_DB", "OPENIDP_REDIS_PASSWORD"} {
		os.Unsetenv(k)
	}
	c := FromEnv()
	if c.RedisAddr != "" {
		t.Fatalf("RedisAddr default = %q; want empty", c.RedisAddr)
	}
	if c.RedisDB != 0 {
		t.Fatalf("RedisDB default = %d; want 0", c.RedisDB)
	}
	if c.RedisPassword != "" {
		t.Fatalf("RedisPassword default = %q; want empty", c.RedisPassword)
	}
}

func TestTrustProxyDefaultsToTrue(t *testing.T) {
	// 默认必须信任反向代理：OpenIdP 典型部署在 CDN / 反向代理之后，
	// 否则限流、审计与归属地会退化成代理自身 IP。
	os.Unsetenv("OPENIDP_TRUST_PROXY")
	if !resolveTrustProxy() {
		t.Fatal("TrustProxy 默认值应为 true")
	}
}

func TestTrustProxyExplicitDisable(t *testing.T) {
	// 显式关闭（none / false 等）时必须生效，供「可被任意内网主机直连」的部署使用。
	for _, v := range []string{"none", "false", "0", "off"} {
		t.Setenv("OPENIDP_TRUST_PROXY", v)
		if resolveTrustProxy() {
			t.Fatalf("OPENIDP_TRUST_PROXY=%q 时应关闭", v)
		}
	}
}

func TestTrustProxyExplicitEnable(t *testing.T) {
	for _, v := range []string{"true", "1", "yes", "on"} {
		t.Setenv("OPENIDP_TRUST_PROXY", v)
		if !resolveTrustProxy() {
			t.Fatalf("OPENIDP_TRUST_PROXY=%q 时应开启", v)
		}
	}
}

func TestTimezoneDefault(t *testing.T) {
	os.Unsetenv("OPENIDP_TIMEZONE")
	c := FromEnv()
	if c.Timezone != "Asia/Shanghai" {
		t.Fatalf("Timezone 默认值 = %q; want Asia/Shanghai", c.Timezone)
	}
}

func TestTimezoneFromEnv(t *testing.T) {
	t.Setenv("OPENIDP_TIMEZONE", "America/New_York")
	c := FromEnv()
	if c.Timezone != "America/New_York" {
		t.Fatalf("Timezone = %q; want America/New_York", c.Timezone)
	}
}

func TestTimezoneUTC(t *testing.T) {
	t.Setenv("OPENIDP_TIMEZONE", "UTC")
	c := FromEnv()
	if c.Timezone != "UTC" {
		t.Fatalf("Timezone = %q; want UTC", c.Timezone)
	}
}
