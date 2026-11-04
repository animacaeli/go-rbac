package cache

import (
	"context"
	"time"
)

// NoopCache 永不命中、写入即丢弃。默认实现：不使用 Redis 时系统的正常形态。
// 整数操作同样为空：鉴权路径每次回源数据库，授权变更无需失效。
type NoopCache struct{}

var _ PermissionCache = NoopCache{}

// NewNoopCache 返回一个 NoopCache。
func NewNoopCache() NoopCache { return NoopCache{} }

// Get 永远未命中。
func (NoopCache) Get(_ context.Context, _ string) ([]string, bool, error) {
	return nil, false, nil
}

// Set 丢弃写入。
func (NoopCache) Set(_ context.Context, _ string, _ []string, _ time.Duration) error {
	return nil
}

// Delete 无操作。
func (NoopCache) Delete(_ context.Context, _ string) error {
	return nil
}

// GetInt 永远未命中（(0, false, nil) = 生成键 0，语义上有效）。
func (NoopCache) GetInt(_ context.Context, _ string) (int64, bool, error) {
	return 0, false, nil
}

// Incr 无操作，返回 0。
func (NoopCache) Incr(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
