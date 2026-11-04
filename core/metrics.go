package core

import (
	"sync"
	"sync/atomic"
	"time"
)

// CountingMetrics 是 Metrics 的轻量内存实现：原子计数 + 快照读取。
// 适用于业务项目暴露到 expvar / Prometheus / 日志的自适应采集。
type CountingMetrics struct {
	denials  sync.Map // reason -> *atomic.Int64
	hits     atomic.Int64
	misses   atomic.Int64
	duration atomic.Int64 // 累计纳秒
}

var _ Metrics = (*CountingMetrics)(nil)

// NewCountingMetrics 创建计数实现。
func NewCountingMetrics() *CountingMetrics { return &CountingMetrics{} }

// DenialsInc 按原因递增拒绝计数。
func (m *CountingMetrics) DenialsInc(reason string) {
	v, _ := m.denials.LoadOrStore(reason, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

// AuthorizeObserved 记录一次授权判断。
func (m *CountingMetrics) AuthorizeObserved(cacheHit bool, d time.Duration) {
	if cacheHit {
		m.hits.Add(1)
	} else {
		m.misses.Add(1)
	}
	m.duration.Add(int64(d))
}

// MetricsSnapshot 是某一时点的观测快照。
type MetricsSnapshot struct {
	Denials       map[string]int64
	CacheHits     int64
	CacheMisses   int64
	TotalRequests int64
	// AvgDuration 全部请求（命中+未命中）的平均耗时。
	AvgDuration time.Duration
}

// Snapshot 返回当前计数快照。
func (m *CountingMetrics) Snapshot() MetricsSnapshot {
	denials := make(map[string]int64)
	m.denials.Range(func(k, v any) bool {
		denials[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	hits, misses := m.hits.Load(), m.misses.Load()
	total := hits + misses
	var avg time.Duration
	if total > 0 {
		avg = time.Duration(m.duration.Load() / total)
	}
	return MetricsSnapshot{
		Denials:       denials,
		CacheHits:     hits,
		CacheMisses:   misses,
		TotalRequests: total,
		AvgDuration:   avg,
	}
}
