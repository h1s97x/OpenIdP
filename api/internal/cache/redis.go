package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisCache is a Redis-backed implementation of Cache. It relies on Redis TTL
// for expiration and INCR/EXPIRE for atomic rate limiting.
//
// 每个操作都成对提供两个版本：
//   - 导出方法（Get/Set/…）满足 Cache 接口，吞掉错误以保持接口简洁；
//   - 小写方法（get/set/…）向上返回真实错误，供 failover 判断是否该回落到
//     内存后端。区分这两者是必要的：读操作若把「连接失败」与「键不存在」
//     混为一谈，上层就会把故障当成 cache miss，进而静默丢数据。
type redisCache struct {
	client *redis.Client
	opts   Options
}

// isMiss 判断错误是否只是「键不存在」（正常结果，不是故障）。
func isMiss(err error) bool {
	return errors.Is(err, redis.Nil)
}

// newRedis dials Redis and verifies connectivity. It returns an error when the
// connection cannot be established so the caller can degrade to memory.
func newRedis(o Options) (*redisCache, error) {
	pingTimeout := o.PingTimeout
	if pingTimeout <= 0 {
		pingTimeout = 2 * time.Second
	}
	dialTimeout := o.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 3 * time.Second
	}
	client := redis.NewClient(&redis.Options{
		Addr:        o.Addr,
		Password:    o.Password,
		DB:          o.DB,
		DialTimeout: dialTimeout,
		// Redis 宕机时默认会重试 3 次并各自等待拨号超时，单次请求可被拖到 10s 以上。
		// 失败要快速暴露给熔断逻辑，恢复由后台探测协程负责，无需在请求路径上重试。
		MaxRetries: 1,
	})
	rc := &redisCache{client: client, opts: o}
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return rc, nil
}

// ping 供故障恢复探测使用。
func (r *redisCache) ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), r.opts.effectivePingTimeout())
	defer cancel()
	return r.client.Ping(ctx).Err()
}

// ---- 带错误返回的底层操作 ----

func (r *redisCache) get(ctx context.Context, key string) (string, bool, error) {
	v, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if isMiss(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

func (r *redisCache) set(ctx context.Context, key, value string, ttl time.Duration) error {
	if err := r.client.Set(ctx, key, value, ttl).Err(); err != nil {
		return err
	}
	return nil
}

// getDel 使用 Redis 6.2+ 的 GETDEL 命令：单命令原子地读取并删除。
func (r *redisCache) getDel(ctx context.Context, key string) (string, bool, error) {
	v, err := r.client.GetDel(ctx, key).Result()
	if err != nil {
		if isMiss(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

func (r *redisCache) del(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// incr 出错时返回错误，绝不静默返回 1：
// 返回 1 会被限流器判为「第 1 次请求」而放行，等于取消防爆破。
func (r *redisCache) incr(ctx context.Context, key string) (int64, error) {
	n, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	return n, nil
}

// incrWithTTLFallback 在 Lua 脚本不可用时把两次调用压缩为一次 pipeline，
// 尽量缩短 Incr 与 Expire 之间的窗口。
func (r *redisCache) incrWithTTLFallback(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	pipe := r.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		// 连 pipeline 都失败说明连接确实不可用，向上返回错误而不是退回裸 Incr，
		// 否则又退化成「拿不到计数」的放行路径。
		return 0, err
	}
	if err := incr.Err(); err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

// incrWithTTL 用 Lua 脚本把 INCR 与条件 EXPIRE 合成一个原子操作：
// 只有计数为 1（新窗口）或键尚无 TTL 时才设置过期时间，
// 避免多实例并发下 count 判断竞态导致窗口被反复重置。
func (r *redisCache) incrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	res, err := incrWithTTLScript.Run(ctx, r.client, []string{key}, int64(ttl/time.Millisecond)).Result()
	if err != nil {
		return r.incrWithTTLFallback(ctx, key, ttl)
	}
	n, ok := res.(int64)
	if !ok {
		return 0, errors.New("redis: INCRWITHTTL 脚本返回了非整型结果")
	}
	return n, nil
}

func (r *redisCache) expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	ok, err := r.client.Expire(ctx, key, ttl).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}

// incrWithTTLScript 原子地自增计数并设置窗口 TTL（PX 毫秒）。
var incrWithTTLScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if n == 1 or ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return n
`)

// mergeMaxCounter 把熔断期间在内存中累计的计数器合并进 Redis：取两者最大值。
//
// 限流计数是「窗口内请求数」，只增不减，取大值可以保证熔断期间的累计量不被丢弃，
// 也不会把 Redis 中已经更高的计数改小。TTL 仅在 Redis 侧无匹配值、需要写入时才设置，
// 避免把正在生效的窗口往后推（那等于无限延长限流窗口）。
var mergeMaxCounterScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
local mine = tonumber(ARGV[1])
if not cur then
  redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
  return mine
end
local theirs = tonumber(cur)
if not theirs or mine > theirs then
  redis.call('SET', KEYS[1], ARGV[1], 'KEEPTTL')
  return mine
end
return theirs
`)

// mergeMaxCounter 见 mergeMaxCounterScript 的说明。ttl <= 0 时按键无过期处理。
func (r *redisCache) mergeMaxCounter(key, value string, ttl time.Duration) error {
	ms := ttl.Milliseconds()
	if ttl <= 0 {
		ms = 0
	}
	// 回填是后台动作，不随任何请求取消而中断，故用独立的短超时上下文。
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := mergeMaxCounterScript.Run(ctx, r.client, []string{key}, value, ms).Result()
	return err
}

// setIfAbsent 仅在键不存在时写入（SET NX）。
//
// 回填时对非计数器键（CSRF/step-up/consent 令牌、一次性设备码）使用它：
// Redis 中若已有同名键，说明那才是权威值，内存副本属于过期残留，不应覆盖。
func (r *redisCache) setIfAbsent(key, value string, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return r.client.SetNX(ctx, key, value, ttl).Err()
}

// ---- Cache 接口实现（吞掉错误，供直接使用 redisCache 的场景） ----

func (r *redisCache) Get(ctx context.Context, key string) (string, bool) {
	v, ok, _ := r.get(ctx, key)
	return v, ok
}

func (r *redisCache) Set(ctx context.Context, key, value string, ttl time.Duration) {
	_ = r.set(ctx, key, value, ttl)
}

func (r *redisCache) GetDel(ctx context.Context, key string) (string, bool) {
	v, ok, _ := r.getDel(ctx, key)
	return v, ok
}

func (r *redisCache) Del(ctx context.Context, key string) {
	_ = r.del(ctx, key)
}

func (r *redisCache) Incr(ctx context.Context, key string) (int64, error) {
	return r.incr(ctx, key)
}

func (r *redisCache) IncrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return r.incrWithTTL(ctx, key, ttl)
}

func (r *redisCache) Expire(ctx context.Context, key string, ttl time.Duration) bool {
	ok, _ := r.expire(ctx, key, ttl)
	return ok
}

// Stats 上报当前 DB 的键数量；字节数留空（见 Stats 的说明）。
// 短超时：这是运维展示用的旁路查询，不该因为 Redis 卡住而拖住接口。
func (r *redisCache) Stats() Stats {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	n, err := r.client.DBSize(ctx).Result()
	if err != nil {
		return Stats{}
	}
	return Stats{Entries: int(n)}
}

func (r *redisCache) Kind() string { return "redis" }

func (r *redisCache) Close() error { return r.client.Close() }
