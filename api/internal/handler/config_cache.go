package handler

import (
	"reflect"
	"sync"
	"time"

	"github.com/h1s97x/openidp/api/internal/models"
)

// 单行配置表（站点设置 / 安全策略 / 邮件 / 人机验证）在一次请求里会被反复读取，
// 例如会话轮询会连带触发数次 loadSiteSetting / loadSecurityPolicy。
// 这些表只在管理后台被修改，改动频率极低，因此加一层带短 TTL 的进程内缓存，
// 用一次潜在的秒级延迟换取每个请求数次数据库往返。
const configCacheTTL = 5 * time.Second

// configCache 缓存单行配置。各类配置共用一个过期时间：
// 任意一项回源时统一顺延，避免过期时间分散造成反复回源。
type configCache struct {
	mu    sync.RWMutex
	until time.Time

	site     *models.SiteSetting
	security *models.SecurityPolicy
	mail     *models.MailSetting
	captcha  *models.CaptchaSetting
	sms      *models.SmsSetting
	storage  *models.StorageSetting
	location *models.LocationSetting
	audit    *models.AuditSetting
	cleanup  *models.DataCleanupSetting
}

// invalidate 清空缓存，供管理后台写操作后立即生效。
func (c *configCache) invalidate() {
	c.mu.Lock()
	c.until = time.Time{}
	c.site = nil
	c.security = nil
	c.mail = nil
	c.captcha = nil
	c.sms = nil
	c.storage = nil
	c.location = nil
	c.audit = nil
	c.cleanup = nil
	c.mu.Unlock()
}

// cached 是单行配置的通用读取流程：命中且未过期则直接返回副本，否则回源并写入缓存。
// 回源在锁外执行，并发下可能有少量重复查询，但不会互相阻塞。
//
// 返回值一律是缓存对象的**副本**，见 cloneConfig 的说明。
func cached[T any](c *configCache, peek func(*configCache) *T, store func(*configCache, *T), fetch func() *T) *T {
	c.mu.RLock()
	if v := peek(c); v != nil && time.Now().Before(c.until) {
		cp := cloneConfig(v)
		c.mu.RUnlock()
		return cp
	}
	c.mu.RUnlock()

	v := fetch()
	store(c, v)
	return cloneConfig(v)
}

// cloneConfig 返回配置对象的深拷贝（递归复制切片 / 映射 / 指针指向的内容）。
//
// 缓存里的对象是全进程共享的。若把指针直接交给调用方，管理后台的写操作会在
// 缓存对象上**原地赋值**（`ms.Host = ...`），带来两个问题：
//  1. 与并发读方（loadSiteSetting / loadSecurityPolicy 等）构成数据竞争；
//  2. DB 写失败时 handler 直接 return、不会 invalidate，被改动的配置（例如
//     安全策略里的 PasswordLoginEnabled）会留在缓存里继续生效到 TTL 过期。
//
// 对外只返回副本后，这两点都从根上消除：调用方改自己的副本，缓存不受影响；
// 写成功再由 handler 调用 invalidate() 让新配置立即生效。
func cloneConfig[T any](v *T) *T {
	if v == nil {
		return nil
	}
	cp := *v
	deepCopyValue(reflect.ValueOf(&cp).Elem())
	return &cp
}

// deepCopyValue 就地递归复制引用类型（切片 / 映射 / 指针 / 数组）指向的内容。
// 其余类型（数值、字符串、时间、以及不可导出的字段）都是值语义，无需处理。
func deepCopyValue(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		nv := reflect.New(v.Type().Elem())
		nv.Elem().Set(v.Elem())
		deepCopyValue(nv.Elem())
		v.Set(nv)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			// 不可导出的字段 CanSet() 为 false，跳过（对它们调用 Set 会 panic）。
			if f := v.Field(i); f.CanSet() {
				deepCopyValue(f)
			}
		}
	case reflect.Slice:
		if v.IsNil() {
			return
		}
		cp := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(cp, v)
		v.Set(cp)
		for i := 0; i < cp.Len(); i++ {
			deepCopyValue(cp.Index(i))
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		cp := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			cp.SetMapIndex(iter.Key(), iter.Value())
		}
		v.Set(cp)
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			deepCopyValue(v.Index(i))
		}
	}
}

func peekSite(c *configCache) *models.SiteSetting    { return c.site }
func peekSec(c *configCache) *models.SecurityPolicy  { return c.security }
func peekMail(c *configCache) *models.MailSetting    { return c.mail }
func peekCapt(c *configCache) *models.CaptchaSetting { return c.captcha }
func peekSms(c *configCache) *models.SmsSetting      { return c.sms }

func peekStorage(c *configCache) *models.StorageSetting     { return c.storage }
func peekLocation(c *configCache) *models.LocationSetting   { return c.location }
func peekAudit(c *configCache) *models.AuditSetting         { return c.audit }
func peekCleanup(c *configCache) *models.DataCleanupSetting { return c.cleanup }

func storeSite(c *configCache, v *models.SiteSetting) {
	c.mu.Lock()
	c.site = v
	c.until = time.Now().Add(configCacheTTL)
	c.mu.Unlock()
}

func storeSec(c *configCache, v *models.SecurityPolicy) {
	c.mu.Lock()
	c.security = v
	c.until = time.Now().Add(configCacheTTL)
	c.mu.Unlock()
}

func storeMail(c *configCache, v *models.MailSetting) {
	c.mu.Lock()
	c.mail = v
	c.until = time.Now().Add(configCacheTTL)
	c.mu.Unlock()
}

func storeCapt(c *configCache, v *models.CaptchaSetting) {
	c.mu.Lock()
	c.captcha = v
	c.until = time.Now().Add(configCacheTTL)
	c.mu.Unlock()
}

func storeSms(c *configCache, v *models.SmsSetting) {
	c.mu.Lock()
	c.sms = v
	c.until = time.Now().Add(configCacheTTL)
	c.mu.Unlock()
}

func storeStorage(c *configCache, v *models.StorageSetting) {
	c.mu.Lock()
	c.storage = v
	c.until = time.Now().Add(configCacheTTL)
	c.mu.Unlock()
}

func storeLocation(c *configCache, v *models.LocationSetting) {
	c.mu.Lock()
	c.location = v
	c.until = time.Now().Add(configCacheTTL)
	c.mu.Unlock()
}

func storeAudit(c *configCache, v *models.AuditSetting) {
	c.mu.Lock()
	c.audit = v
	c.until = time.Now().Add(configCacheTTL)
	c.mu.Unlock()
}

func storeCleanup(c *configCache, v *models.DataCleanupSetting) {
	c.mu.Lock()
	c.cleanup = v
	c.until = time.Now().Add(configCacheTTL)
	c.mu.Unlock()
}
