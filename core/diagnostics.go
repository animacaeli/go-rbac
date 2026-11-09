package core

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/animacaeli/go-rbac/cache"
)

// 运行模式（§1.2 开箱即用 / 可选高级能力）。
const (
	// CacheModeSimple：默认。NoopCache，每次鉴权回源数据库——行为最简单，
	// 无缓存一致性面。适合小型项目与默认接入。
	CacheModeSimple = "simple"
	// CacheModeCached：注入 Redis 等实现后自动进入。版本号 + epoch 两级失效、
	// 写前复核、singleflight、基线恢复协议。适合有性能要求的生产环境。
	CacheModeCached = "cached"
)

// CacheDiagnostics 是缓存一致性诊断快照（运维排障："为什么权限没失效"）。
type CacheDiagnostics struct {
	// Mode 当前运行模式（simple / cached）。
	Mode string `json:"mode"`
	// Scope 授权域。
	Scope string `json:"scope"`
	// SubjectID 被诊断主体（按需提供）。
	SubjectID string `json:"subject_id,omitempty"`

	// 授权域 epoch 计数器状态。
	EpochExists bool  `json:"epoch_exists"`
	EpochValue  int64 `json:"epoch_value"`

	// 全局（跨租户）epoch 计数器状态：权限表为全局定义，权限禁用/同步递增它。
	GlobalEpochExists bool  `json:"global_epoch_exists"`
	GlobalEpochValue  int64 `json:"global_epoch_value"`

	// 主体版本计数器状态（SubjectID 为空时不探测）。
	SubjectVersionExists bool  `json:"subject_version_exists"`
	SubjectVersionValue  int64 `json:"subject_version_value"`

	// Generation 当前生成键（epoch<<32|version）；PermEntryExists 表示
	// 该生成键下是否存在权限条目（存在却疑似陈旧时优先怀疑失效链路）。
	Generation      int64 `json:"generation"`
	PermEntryExists bool  `json:"perm_entry_exists"`

	// InvalidationAttempts / InvalidationFailures：本进程生命周期内的
	// 失效递增尝试与失败计数（失败即 ErrInvalidationFailedAfterCommit 路径）。
	InvalidationAttempts int64 `json:"invalidation_attempts"`
	InvalidationFailures int64 `json:"invalidation_failures"`
}

// AuthorizationService 的失效计数器（诊断用）。
type invCounters struct {
	attempts int64
	failures int64
}

// cacheMode 推断运行模式：NoopCache（值或指针）→ simple，其余 → cached。
func cacheMode(cch cache.PermissionCache) string {
	switch cch.(type) {
	case cache.NoopCache, *cache.NoopCache:
		return CacheModeSimple
	default:
		return CacheModeCached
	}
}

// DiagnoseCache 探测缓存一致性状态。ac 仅用于定位主体（不执行授权判断，
// 不触达数据库）。探测失败（如 Redis 不可达）返回错误——诊断接口本身
// 不允许吞故障。
func (s *AuthorizationService) DiagnoseCache(ctx context.Context, ac AuthorizationContext) (CacheDiagnostics, error) {
	d := CacheDiagnostics{
		Mode:                 cacheMode(s.cch),
		Scope:                ac.Scope(),
		SubjectID:            ac.SubjectID.String(),
		InvalidationAttempts: atomic.LoadInt64(&s.inv.attempts),
		InvalidationFailures: atomic.LoadInt64(&s.inv.failures),
	}

	var epoch, global, version int64
	var ok bool
	epoch, ok, err := s.cch.GetInt(ctx, epochKey(d.Scope))
	if err != nil {
		return d, fmt.Errorf("rbac: diagnose epoch: %w", err)
	}
	d.EpochExists, d.EpochValue = ok, epoch

	global, ok, err = s.cch.GetInt(ctx, globalEpochKey())
	if err != nil {
		return d, fmt.Errorf("rbac: diagnose global epoch: %w", err)
	}
	d.GlobalEpochExists, d.GlobalEpochValue = ok, global

	if ac.SubjectID != "" {
		version, ok, err = s.cch.GetInt(ctx, subjectVersionKey(d.Scope, d.SubjectID))
		if err != nil {
			return d, fmt.Errorf("rbac: diagnose subject version: %w", err)
		}
		d.SubjectVersionExists, d.SubjectVersionValue = ok, version
	}

	if err := validateCounters(counterValues{epoch: epoch, globalEpoch: global, subjectVersion: version}); err != nil {
		return d, err
	}
	d.Generation = generationKey(epoch, global, version)
	if ac.SubjectID != "" {
		_, exists, err := s.cch.Get(ctx, subjectPermKey(d.Scope, d.SubjectID, d.Generation))
		if err != nil {
			return d, fmt.Errorf("rbac: diagnose perm entry: %w", err)
		}
		d.PermEntryExists = exists
	}
	return d, nil
}
