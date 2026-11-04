package cache

import (
	"context"
	"time"
)

// NoopCache 永不命中、写入即丢弃。默认实现：不使用 Redis 时系统的正常形态。
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
