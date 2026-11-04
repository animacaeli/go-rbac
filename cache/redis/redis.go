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

// Set 写入权限集合，带 TTL。
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
		// 值损坏视同不存在：调用方以默认生成键继续，行为安全。
		return 0, false, nil
	}
	return v, true, nil
}

// Incr 原子递增整数键并返回新值（键不存在时 0 → 1）。
func (c *Cache) Incr(ctx context.Context, key string) (int64, error) {
	v, err := c.cli.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("rbac/cache/redis: incr %s: %w", key, err)
	}
	return v, nil
}
