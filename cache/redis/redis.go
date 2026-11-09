// Package redis 提供 PermissionCache 的 Redis 实现（Phase 2，§3.3）。
//
// 本包完全自包含（逃生舱规则：不共享库内胶水代码，仅依赖 cache 接口），
// 未来若抽取为子 Module 是机械操作。推荐配合 rbac.WithCache 使用：
//
//	cli := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
//	app, err := rbac.New(
//	    rbac.WithDB(db),
//	    rbac.WithCache(rediscache.New(cli)),
//	)
//
// 故障语义（§6.6）：Redis 故障时错误向上返回——鉴权路径由 Core 回源数据库，
// 管理接口的版本递增失败会使操作整体报错（权限管理在 Redis 故障期间不可用，
// 这是"可用性换一致性"的刻意选择）。
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache 实现 cache.PermissionCache。
type Cache struct {
	cli redis.UniversalClient
}

// New 以 go-redis 客户端构造。客户端生命周期（连接、关闭）由业务项目负责。
func New(cli redis.UniversalClient) *Cache {
	return &Cache{cli: cli}
}

// Get 读取权限集合（JSON 数组）。键不存在返回 (nil, false, nil)。
func (c *Cache) Get(ctx context.Context, key string) ([]string, bool, error) {
	raw, err := c.cli.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("rbac/cache/redis: get %s: %w", key, err)
	}
	var perms []string
	if err := json.Unmarshal(raw, &perms); err != nil {
		// 值损坏视同未命中，回源后由写回覆盖修复。
		return nil, false, nil
	}
	return perms, true, nil
}

// Set 写入权限集合，带 TTL。ttl <= 0 表示永不过期（go-redis 语义）；权限
// 条目必须带 TTL，调用方应始终传正值（Core 的写回路径保证如此）。
func (c *Cache) Set(ctx context.Context, key string, permissions []string, ttl time.Duration) error {
	raw, err := json.Marshal(permissions)
	if err != nil {
		return fmt.Errorf("rbac/cache/redis: marshal: %w", err)
	}
	if err := c.cli.Set(ctx, key, raw, ttl).Err(); err != nil {
		return fmt.Errorf("rbac/cache/redis: set %s: %w", key, err)
	}
	return nil
}

// Delete 删除键。
func (c *Cache) Delete(ctx context.Context, key string) error {
	if err := c.cli.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("rbac/cache/redis: del %s: %w", key, err)
	}
	return nil
}

// GetInt 读取整数键（版本号 / epoch）。键不存在返回 (0, false, nil)。
func (c *Cache) GetInt(ctx context.Context, key string) (int64, bool, error) {
	raw, err := c.cli.Get(ctx, key).Result()
	if err == redis.Nil {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("rbac/cache/redis: get %s: %w", key, err)
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		// 值损坏 = 缓存状态不可信：必须返回错误，让调用方旁路缓存并
		// 跳过写回。当作"不存在"处理会使生成键回退到 0，可能命中
		// 旧生成键下已撤销的权限集合（§6.2 不变性被键损坏打破）。
		return 0, false, fmt.Errorf("rbac/cache/redis: corrupt integer at %s: %w", key, err)
	}
	return v, true, nil
}

// GetInts 以 MGET 批量读取整数键（cache.IntBatchReader）。
// 缺失键返回 found=false；任一值损坏返回错误（缓存状态不可信，由调用方回退）。
func (c *Cache) GetInts(ctx context.Context, keys []string) ([]int64, []bool, error) {
	raws, err := c.cli.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, nil, fmt.Errorf("rbac/cache/redis: mget: %w", err)
	}
	values := make([]int64, len(keys))
	found := make([]bool, len(keys))
	for i, raw := range raws {
		if raw == nil {
			continue
		}
		str, ok := raw.(string)
		if !ok {
			return nil, nil, fmt.Errorf("rbac/cache/redis: mget %s: unexpected value type %T", keys[i], raw)
		}
		v, perr := strconv.ParseInt(str, 10, 64)
		if perr != nil {
			return nil, nil, fmt.Errorf("rbac/cache/redis: corrupt integer at %s: %w", keys[i], perr)
		}
		values[i], found[i] = v, true
	}
	return values, found, nil
}

// setIntMaxScript 原子单调写：当前值缺失 / 不可解析（损坏自愈）/ 小于
// 新值时才写入；旧值永不覆盖新值。恢复×同步乱序并发下副本只会前进。
var setIntMaxScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if not cur then
  redis.call('SET', KEYS[1], ARGV[1])
  return 1
end
local curNum = tonumber(cur)
if not curNum or curNum < tonumber(ARGV[1]) then
  redis.call('SET', KEYS[1], ARGV[1])
  return 1
end
return 0
`)

// SetIntMax 单调提升整数键（DB 权威版本的同步与恢复原语，§6.2）。
func (c *Cache) SetIntMax(ctx context.Context, key string, value int64) error {
	if err := setIntMaxScript.Run(ctx, c.cli, []string{key}, strconv.FormatInt(value, 10)).Err(); err != nil {
		return fmt.Errorf("rbac/cache/redis: setintmax %s: %w", key, err)
	}
	return nil
}
