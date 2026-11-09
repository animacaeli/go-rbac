package core

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/animacaeli/go-rbac/cache"
	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/model"
	"golang.org/x/sync/singleflight"
)

// AuthorizationService 实现 Authorizer（§4.3），并统一负责缓存 key 构造、
// 版本号 + epoch 两级失效（§6）与缓存击穿防护。
//
// == 缓存一致性机制（§6，Phase 2 形态） ==
//
// 三族 key（§6.1）：
//
//	rbac:{scope}:epoch                          # 全局 epoch（粗粒度失效）
//	rbac:{scope}:subject:{subject_id}:version   # 主体权限版本号
//	rbac:{scope}:subject:{subject_id}:perm:v{version}
//
// 其中 perm key 的 version 是"生成键"：gen = epoch<<32 | subjectVersion。
// 两个整数合并进一个 key 后缀，与 §6.1 的 key 形状一致，同时让 epoch 递增
// （权限禁用等低频全局事件）天然使所有旧生成键不可达——全员冷启动一次（§6.3）。
//
// 读取流程（§6.2）：
//  1. 读取 epoch 与版本号，得到生成键 gen
//  2. 读取 perm:v{gen}；命中直接返回
//  3. 未命中 → singleflight 合并并发回源（§6.8 击穿防护）→ 查询数据库
//  4. 写回前复核生成键未变；已变则丢弃结果重新走流程（最多重试一次，
//     仍不稳定则返回未缓存的数据库结果——正确性不受影响）
//  5. 写回 TTL 不超过主体最近一条临时授权的到期时间（§6.5）
//
// 写入流程（§6.2 不变性，承重墙）：版本号只允许"落后于"数据，永远不"超前"。
// 服务层先提交数据库事务，成功后才递增版本 / epoch；递增失败时管理接口
// 整体报错（§6.6/§6.7），不出现半成功状态。
//
// TTL 是垃圾回收机制而非正确性机制：旧生成键在 TTL 内自然过期。
type AuthorizationService struct {
	repo     repository.AuthorizationRepo
	counters repository.CountersRepo
	cch      cache.PermissionCache
	checker  SubjectStatusChecker
	metrics  Metrics
	ttl      time.Duration
	sf       singleflight.Group

	// tenantRequired 由 tenant 模块经 rbac.App.EnableTenantScope 打开：
	// AuthorizationContext.TenantID 从"必须为空"变为"必须提供"（§2.9）。
	tenantRequired bool

	// inv：失效递增尝试/失败计数（CacheDiagnostics 暴露）。
	inv invCounters
}

// SetTenantScopeRequired 切换多租户校验策略（tenant 模块装配期调用）。
func (s *AuthorizationService) SetTenantScopeRequired(required bool) {
	s.tenantRequired = required
}

// validateAC 按当前租户策略校验授权上下文。
// v1（未启用租户）：TenantID 必须为空串；启用租户：必须非空（§2.9 fail closed）。
func (s *AuthorizationService) validateAC(ac AuthorizationContext) error {
	if ac.SubjectID.IsEmpty() || len(ac.SubjectID) > model.SubjectIDMaxLength {
		return ErrInvalidSubjectID
	}
	if s.tenantRequired {
		if ac.TenantID == "" {
			return ErrTenantRequired
		}
		if !ValidTenantID(ac.TenantID) {
			return fmt.Errorf("%w: %q", ErrInvalidTenantID, ac.TenantID)
		}
	} else if ac.TenantID != "" {
		return ErrTenantNotSupported
	}
	return nil
}

// TenantIDMaxLength 与 tenant 迁移的列宽（VARCHAR(64)）一致。
const TenantIDMaxLength = 64

// ValidTenantID 校验授权域标识：长度 <= 64、字符集 [A-Za-z0-9_.-]，
// 且不占用保留 scope（"default" 平台域、"!global" 全局计数器）。
// 字符集限制是缓存/计数器键（"rbac:{scope}:subject:..."）的结构性保护。
func ValidTenantID(tenantID string) bool {
	if tenantID == "" || len(tenantID) > TenantIDMaxLength {
		return false
	}
	if strings.EqualFold(tenantID, DefaultScope) || strings.EqualFold(tenantID, repository.GlobalScope) {
		return false
	}
	for _, r := range tenantID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}

var _ Authorizer = (*AuthorizationService)(nil)

// NewAuthorizationService 构造授权服务。ttl <= 0 时默认 5 分钟。
func NewAuthorizationService(
	repo repository.AuthorizationRepo,
	counters repository.CountersRepo,
	cch cache.PermissionCache,
	checker SubjectStatusChecker,
	metrics Metrics,
	ttl time.Duration,
) *AuthorizationService {
	if cch == nil {
		cch = cache.NoopCache{}
	}
	if metrics == nil {
		metrics = NoopMetrics{}
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &AuthorizationService{repo: repo, counters: counters, cch: cch, checker: checker, metrics: metrics, ttl: ttl}
}

// noopMarker 是"无缓存"实现的可选标记（cache.NoopCache 及其包装）。
type noopMarker interface{ IsNoop() bool }

// isNoopCache 判断缓存实现是否等价于 NoopCache。
func isNoopCache(c cache.PermissionCache) bool {
	if _, ok := c.(noopMarker); ok {
		return true
	}
	switch c.(type) {
	case cache.NoopCache, *cache.NoopCache:
		return true
	default:
		return false
	}
}

// loaded 是一次授权状态装载的结果。
type loaded struct {
	permissions map[string]struct{}
	isSuper     bool
}

// ---- key 构造（§6.1，Core 统一负责） ----

func epochKey(scope string) string {
	return "rbac:" + scope + ":epoch"
}

// globalEpochKey 是全局（跨租户）epoch 的缓存键：权限定义表是全局的，
// 权限禁用/同步必须使所有授权域的生成键失效（§6.3）。
func globalEpochKey() string {
	return "rbac:" + repository.GlobalScope + ":epoch"
}

// subject_id 是外部不透明标识：库表列（迁移 0004）与缓存/计数器键都按
// 二进制比较，大小写与重音敏感。不要在此处做大小写折叠——那会与数据库的
// 二进制语义不一致，导致撤销只命中其中一种写法（第八轮复审 P1-03）。
func subjectVersionKey(scope, subjectID string) string {
	return "rbac:" + scope + ":subject:" + subjectID + ":version"
}

func subjectPermKey(scope, subjectID string, gen int64) string {
	return "rbac:" + scope + ":subject:" + subjectID + ":perm:v" + strconv.FormatInt(gen, 10)
}

// generationKey 合并"授权域 epoch + 全局 epoch"与主体版本号为单个生成键。
// subjectVersion 使用低 32 位（现实中不可能触达），epoch 和占高位；
// 三个计数器都单调不减，任一递增都会严格增大生成键，使旧 perm key 不可达。
//
// 全局 epoch 参与合成是"权限表全局、授权域按租户"的必然结果：单租户域
// epoch 无法表达跨租户的权限禁用（外部评审第八轮 P0）。
func generationKey(epoch, globalEpoch, subjectVersion int64) int64 {
	return (epoch+globalEpoch)<<32 | subjectVersion
}

// counterValues 是一次授权域计数器读取结果。
type counterValues struct {
	epoch          int64
	globalEpoch    int64
	subjectVersion int64
}

// 生成键的数值边界：gen = (epoch+global)<<32 | subjectVersion。
//   - subjectVersion 占低 32 位（必须 <= 2^32-1）；
//   - epoch+global 占高位（左移 32 后必须不超过 int64）。
//
// 计数器在现实中不可能触达这些量级，但一致性协议以"单调且不碰撞"为不变量，
// 因此把边界显式化：越界时 fail closed，而不是静默截断/溢出后命中旧键。
const (
	maxSubjectVersion = int64(1<<32 - 1)
	maxEpochSum       = int64(1<<31 - 1) // MaxInt64 >> 32
)

// validateCounters 校验计数器是否仍在生成键可表达的范围内。
func validateCounters(cv counterValues) error {
	if cv.subjectVersion < 0 || cv.subjectVersion > maxSubjectVersion {
		return fmt.Errorf("%w: subject version %d (max %d)", ErrCounterOverflow, cv.subjectVersion, maxSubjectVersion)
	}
	// 先做单项范围检查，再用减法做安全求和：epoch+global 直接相加在
	// MaxInt64 附近会溢出为负数，从而绕过上限判断（第九轮复审 P2）。
	if cv.epoch < 0 || cv.globalEpoch < 0 ||
		cv.epoch > maxEpochSum || cv.globalEpoch > maxEpochSum ||
		cv.epoch > maxEpochSum-cv.globalEpoch {
		return fmt.Errorf("%w: epoch %d + global epoch %d (max %d)",
			ErrCounterOverflow, cv.epoch, cv.globalEpoch, maxEpochSum)
	}
	return nil
}

// readCounters 读取 epoch / 全局 epoch / 主体版本三个计数器副本。
// 实现缓存支持批量读时合并为一次往返（cache.IntBatchReader）。
// ok=false 表示有键缺失（调用方回退数据库权威值）；err 非 nil 表示缓存故障。
func (s *AuthorizationService) readCounters(ctx context.Context, scope, subject string) (cv counterValues, ok bool, err error) {
	keys := [3]string{epochKey(scope), globalEpochKey(), subjectVersionKey(scope, subject)}
	if batch, canBatch := s.cch.(cache.IntBatchReader); canBatch {
		vals, found, berr := batch.GetInts(ctx, keys[:])
		switch {
		case berr == nil && len(vals) == len(keys) && len(found) == len(keys):
			if !found[0] || !found[1] || !found[2] {
				return counterValues{}, false, nil
			}
			cv := counterValues{epoch: vals[0], globalEpoch: vals[1], subjectVersion: vals[2]}
			if err := validateCounters(cv); err != nil {
				return counterValues{}, false, err
			}
			return cv, true, nil
		default:
			// 批量读失败（典型：Redis Cluster 中三个键落在不同 slot，
			// MGET 返回 CROSSSLOT）→ 退回逐键读取；逐键失败才视为缓存故障。
		}
	}
	for i, key := range keys {
		v, found, gerr := s.cch.GetInt(ctx, key)
		if gerr != nil {
			return counterValues{}, false, gerr
		}
		if !found {
			return counterValues{}, false, nil
		}
		switch i {
		case 0:
			cv.epoch = v
		case 1:
			cv.globalEpoch = v
		case 2:
			cv.subjectVersion = v
		}
	}
	if err := validateCounters(cv); err != nil {
		return counterValues{}, false, err
	}
	return cv, true, nil
}

// load 装载主体的有效授权状态。
func (s *AuthorizationService) load(ctx context.Context, ac AuthorizationContext) (loaded, error) {
	start := time.Now()
	cacheHit := false
	defer func() {
		s.metrics.AuthorizeObserved(cacheHit, time.Since(start))
	}()

	if err := s.validateAC(ac); err != nil {
		return loaded{}, err
	}
	// 授权域注入 ctx：租户隔离仓储据此过滤；缓存 key 由 ac.Scope() 构造（§6.1）。
	ctx = ContextWithTenant(ctx, ac.TenantID)

	if s.checker != nil {
		active, err := s.checker.IsSubjectActive(ctx, ac.SubjectID)
		if err != nil {
			return loaded{}, fmt.Errorf("rbac: subject status check failed (fail closed): %w", err)
		}
		if !active {
			return loaded{}, ErrSubjectInactive
		}
	}

	// 最多两轮：生成键在回源期间变化时丢弃结果重走流程（§6.2 第 5 步）。
	// 超管状态以哨兵码参与缓存：热路径（含超管）零数据库查询（§9.4）。
	for attempt := 0; attempt < 2; attempt++ {
		l, hit, unstable, err := s.loadOnce(ctx, ac)
		if err != nil {
			return loaded{}, err
		}
		if hit {
			cacheHit = true
		}
		if !unstable {
			return l, nil
		}
	}
	// 两轮均不稳定（高频变更窗口）：返回未缓存的数据库结果，保守正确。
	set, isSuper, err := s.loadFromDB(ctx, ac)
	if err != nil {
		return loaded{}, err
	}
	return loaded{permissions: set, isSuper: isSuper}, nil
}

// loadOnce 执行一轮"读生成键 → 读缓存 → （singleflight）回源 + 复核 + 写回"。
// unstable=true 表示写回前生成键已变，调用方应重试。
func (s *AuthorizationService) loadOnce(ctx context.Context, ac AuthorizationContext) (l loaded, hit, unstable bool, err error) {
	scope := ac.Scope()
	subject := ac.SubjectID.String()

	// Simple 模式（NoopCache）：无缓存即无生成键语义——直接回源数据库，
	// 不走计数器协议（否则每次鉴权额外 +4 次权威计数器查询，Simple 模式
	// 的性能契约是"仅原有聚合查询"）。
	if isNoopCache(s.cch) {
		set, isSuper, err := s.loadFromDB(ctx, ac)
		if err != nil {
			return loaded{}, false, false, err
		}
		return loaded{permissions: set, isSuper: isSuper}, false, false, nil
	}

	// 生成键协议（§6.2 / §6.1，DB 权威版，Cached 模式）：
	//   - Redis 计数器是 rbac_counters 权威值的缓存副本；
	//   - 缺失 / 损坏 / 故障 → 从数据库读取权威值并 SetIntMax 单调回填
	//     （回填的是真实版本号而非重置归零——结构上不存在"重建值与历史
	//     生成键碰撞"），随后照常走缓存/回源；
	//   - 任何时刻生成键均取自权威值或其忠实副本：权威值只增不减，
	//     旧生成键下的陈旧条目天然不可达。
	cv, countersOK, cErr := s.readCounters(ctx, scope, subject)
	if cErr != nil || !countersOK {
		var rerr error
		cv, rerr = s.recoverCountersFromDB(ctx, scope, subject, cErr)
		if rerr != nil {
			// 数据库也不可用：回源鉴权数据（不读缓存），fail-closed 语义由
			// 聚合查询错误承载。
			set, isSuper, dbErr := s.loadFromDB(ctx, ac)
			if dbErr != nil {
				return loaded{}, false, false, dbErr
			}
			return loaded{permissions: set, isSuper: isSuper}, false, false, nil
		}
	}

	refGen := generationKey(cv.epoch, cv.globalEpoch, cv.subjectVersion)
	if cached, ok, err := s.cch.Get(ctx, subjectPermKey(scope, subject, refGen)); err == nil && ok {
		return parseCached(cached), true, false, nil
	}
	// 未命中 / 故障 → singleflight 合并回源（§6.8）。
	//
	// 共享回源使用 WithoutCancel：剥离首个调用者的取消信号（保留 ctx values），
	// 否则该请求断开会让所有等待者一起失败；调用方自身的取消仍由下面的
	// select 处理，不会阻塞已断开的请求。
	ch := s.sf.DoChan(scope+"/"+subject, func() (any, error) {
		return s.aggregateAndCache(context.WithoutCancel(ctx), ac, refGen)
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return loaded{}, false, false, res.Err
		}
		result, ok := res.Val.(aggregateResult)
		if !ok {
			return loaded{}, false, false, fmt.Errorf("rbac: unexpected singleflight result type %T", res.Val)
		}
		return loaded{permissions: result.set, isSuper: result.isSuper}, false, result.unstable, nil
	case <-ctx.Done():
		return loaded{}, false, false, ctx.Err()
	}
}

type aggregateResult struct {
	set      map[string]struct{}
	isSuper  bool
	unstable bool
}

// superAdminSentinel 是超管状态的缓存哨兵码：含通配符 *，注册中心校验必然
// 拒绝，任何真实权限码都不可能与它冲突。
const superAdminSentinel = "rbac:*super*"

// parseCached 解析缓存集合：含哨兵 → 超管（空集合 + isSuper）。
func parseCached(cached []string) loaded {
	set := make(map[string]struct{}, len(cached))
	for _, code := range cached {
		if code == superAdminSentinel {
			return loaded{permissions: map[string]struct{}{}, isSuper: true}
		}
		set[code] = struct{}{}
	}
	return loaded{permissions: set}
}

// aggregateAndCache 在 singleflight 内执行：二次探测缓存 → 数据库聚合 →
// 复核生成键未变 → 写回。refGen 为外层已确认（缓存副本或 DB 权威值）的生成键。
func (s *AuthorizationService) aggregateAndCache(ctx context.Context, ac AuthorizationContext, refGen int64) (aggregateResult, error) {
	scope := ac.Scope()
	subject := ac.SubjectID.String()

	if cached, hit, err := s.cch.Get(ctx, subjectPermKey(scope, subject, refGen)); err == nil && hit {
		l := parseCached(cached)
		return aggregateResult{set: l.permissions, isSuper: l.isSuper}, nil
	}

	isSuper, err := s.repo.HasBuiltinSuperAdminRole(ctx, subject)
	if err != nil {
		return aggregateResult{}, fmt.Errorf("rbac: check super administrator: %w", err)
	}
	if isSuper {
		// 超管：缓存哨兵集合（TTL 走默认值），Has* 恒真、GetPermissions 空集合。
		_ = s.cch.Set(ctx, subjectPermKey(scope, subject, refGen), []string{superAdminSentinel}, s.ttl)
		return aggregateResult{set: map[string]struct{}{}, isSuper: true}, nil
	}

	// 预读最近到期时间（TTL 上限），与聚合结果一并使用。
	now := time.Now().UTC()
	set, nearest, expiryErr, err := s.aggregate(ctx, ac, now)
	if err != nil {
		return aggregateResult{}, err
	}
	if expiryErr != nil {
		// §6.5：无法确认最近到期时间 → 不写缓存（临时授权不得在到期后
		// 被缓存继续放行），本次返回未缓存数据。
		return aggregateResult{set: set}, nil
	}

	// 写回前复核生成键（§6.2 第 5 步 / §6.4 写前复核）：
	// 副本可读则以副本比较；副本不可读则以 DB 权威值比较
	// （权威值 ≥ 写入时生成键 → 允许写回旧键是安全的：读路径只会用
	// 更高的生成键，写回的旧键天然不被命中——直接跳过写回更简单）。
	gen2, ok, err := s.readCachedGeneration(ctx, scope, subject)
	if err != nil || !ok {
		// 副本不可读：以 DB 权威值兜底比较。
		dbEpoch, e1 := s.counters.Get(ctx, dbEpochKey(scope))
		dbGlobal, e3 := s.counters.Get(ctx, repository.GlobalEpochKey)
		dbVersion, e2 := s.counters.Get(ctx, dbSubjectVersionKey(scope, subject))
		if e1 != nil || e2 != nil || e3 != nil {
			return aggregateResult{set: set}, nil
		}
		if err := validateCounters(counterValues{epoch: dbEpoch, globalEpoch: dbGlobal, subjectVersion: dbVersion}); err != nil {
			return aggregateResult{set: set}, nil
		}
		if generationKey(dbEpoch, dbGlobal, dbVersion) != refGen {
			return aggregateResult{set: set}, nil
		}
	} else if gen2 != refGen {
		return aggregateResult{set: set}, nil
	}

	ttl := s.ttl
	if nearest != nil {
		if bounded := nearest.Sub(now); bounded > 0 && bounded < ttl {
			ttl = bounded
		}
	}
	// 缓存写失败不影响本次鉴权结果（下次回源即可）。
	_ = s.cch.Set(ctx, subjectPermKey(scope, subject, refGen), flatten(set), ttl)
	return aggregateResult{set: set}, nil
}

// recoverCountersFromDB 从数据库读取权威 epoch / 全局 epoch / 主体版本并
// 回填缓存副本。回填失败（Redis 写失败）不致命：生成键仍以权威值参与本次
// 判断，仅下次读仍需回退。
func (s *AuthorizationService) recoverCountersFromDB(ctx context.Context, scope, subject string, _ error) (counterValues, error) {
	epoch, err := s.counters.Get(ctx, dbEpochKey(scope))
	if err != nil {
		return counterValues{}, fmt.Errorf("rbac: recover epoch from db: %w", err)
	}
	global, err := s.counters.Get(ctx, repository.GlobalEpochKey)
	if err != nil {
		return counterValues{}, fmt.Errorf("rbac: recover global epoch from db: %w", err)
	}
	version, err := s.counters.Get(ctx, dbSubjectVersionKey(scope, subject))
	if err != nil {
		return counterValues{}, fmt.Errorf("rbac: recover subject version from db: %w", err)
	}
	// SetIntMax 单调回填（不先删）：Lua 脚本原子处理损坏值
	// （tonumber(cur) 解析失败即视为不可信，原子替换为权威值），
	// 消除"删除与回填之间的并发同步"竞态窗口（§6.2，外部评审第六轮）。
	cv := counterValues{epoch: epoch, globalEpoch: global, subjectVersion: version}
	if verr := validateCounters(cv); verr != nil {
		return counterValues{}, verr
	}
	_ = s.cch.SetIntMax(ctx, epochKey(scope), epoch)
	_ = s.cch.SetIntMax(ctx, globalEpochKey(), global)
	_ = s.cch.SetIntMax(ctx, subjectVersionKey(scope, subject), version)
	return cv, nil
}

// readCachedGeneration 读副本生成键；ok=false 表示副本缺失/不可读。
func (s *AuthorizationService) readCachedGeneration(ctx context.Context, scope, subject string) (int64, bool, error) {
	cv, ok, err := s.readCounters(ctx, scope, subject)
	if err != nil || !ok {
		return 0, false, err
	}
	return generationKey(cv.epoch, cv.globalEpoch, cv.subjectVersion), true, nil
}

// DB 权威计数器键（rbac_counters.k）：与 Redis 键后缀同构、去前缀。
func dbEpochKey(scope string) string { return scope + ":epoch" }

func dbSubjectVersionKey(scope, subject string) string {
	return scope + ":subject:" + subject + ":version"
}

// loadFromDB 直接回源数据库（不读不写缓存），返回集合与超管判定。
func (s *AuthorizationService) loadFromDB(ctx context.Context, ac AuthorizationContext) (map[string]struct{}, bool, error) {
	subject := ac.SubjectID.String()
	isSuper, err := s.repo.HasBuiltinSuperAdminRole(ctx, subject)
	if err != nil {
		return nil, false, fmt.Errorf("rbac: check super administrator: %w", err)
	}
	if isSuper {
		return map[string]struct{}{}, true, nil
	}
	now := time.Now().UTC()
	set, _, _, err := s.aggregate(ctx, ac, now)
	return set, false, err
}

// aggregate 查询数据库并求并集。
// 返回：集合、最近临时授权到期时间（TTL 上限）、到期时间读取错误
// （expiryErr 只影响"能否写缓存"，不影响数据正确性）、主查询错误。
func (s *AuthorizationService) aggregate(ctx context.Context, ac AuthorizationContext, now time.Time) (set map[string]struct{}, nearest *time.Time, expiryErr error, err error) {
	subject := ac.SubjectID.String()

	rolePerms, err := s.repo.EffectiveRolePermissions(ctx, subject)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("rbac: load role permissions: %w", err)
	}
	grantPerms, err := s.repo.EffectiveGrantPermissions(ctx, subject, now)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("rbac: load grant permissions: %w", err)
	}
	nearest, nearestErr := s.repo.NearestGrantExpiry(ctx, subject, now)
	if nearestErr != nil {
		// §6.5：TTL 上限依赖最近到期时间。读取失败时不得按"永久"写缓存——
		// 否则临时授权可能在到期后被缓存继续放行至整个 TTL 结束。
		// 处置：返回数据但不写缓存（cacheUnsafe），下次读取重新尝试。
		nearest = nil
	}

	set = make(map[string]struct{}, len(rolePerms)+len(grantPerms))
	for _, code := range rolePerms {
		set[code] = struct{}{}
	}
	for _, code := range grantPerms {
		set[code] = struct{}{}
	}
	return set, nearest, nearestErr, nil
}

func flatten(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for code := range set {
		out = append(out, code)
	}
	return out
}

// HasPermission 判断主体是否持有权限（字面匹配，v1 无通配符）。
func (s *AuthorizationService) HasPermission(ctx context.Context, ac AuthorizationContext, permission string) (bool, error) {
	if permission == "" {
		return false, ErrNoPermissionDeclared
	}
	state, err := s.load(ctx, ac)
	if err != nil {
		return false, err
	}
	if state.isSuper {
		return true, nil
	}
	_, ok := state.permissions[permission]
	return ok, nil
}

// HasAnyPermission 判断主体是否持有任一权限。
func (s *AuthorizationService) HasAnyPermission(ctx context.Context, ac AuthorizationContext, permissions ...string) (bool, error) {
	if len(permissions) == 0 {
		return false, ErrNoPermissionDeclared
	}
	state, err := s.load(ctx, ac)
	if err != nil {
		return false, err
	}
	if state.isSuper {
		return true, nil
	}
	for _, p := range permissions {
		if _, ok := state.permissions[p]; ok {
			return true, nil
		}
	}
	return false, nil
}

// HasAllPermissions 判断主体是否持有全部权限。
func (s *AuthorizationService) HasAllPermissions(ctx context.Context, ac AuthorizationContext, permissions ...string) (bool, error) {
	if len(permissions) == 0 {
		return false, ErrNoPermissionDeclared
	}
	state, err := s.load(ctx, ac)
	if err != nil {
		return false, err
	}
	if state.isSuper {
		return true, nil
	}
	for _, p := range permissions {
		if _, ok := state.permissions[p]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// GetPermissions 返回主体最终有效权限集合（P(u) = (∪ P(r)) ∪ E(u)，§2.2），
// 按字典序排序保证确定性。超级管理员返回空集合（§4.3：前端应以
// IsSuperAdministrator 单独判断，避免引入通配符语义）。
func (s *AuthorizationService) GetPermissions(ctx context.Context, ac AuthorizationContext) ([]string, error) {
	state, err := s.load(ctx, ac)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(state.permissions))
	for code := range state.permissions {
		out = append(out, code)
	}
	sort.Strings(out)
	return out, nil
}

// IsSuperAdministrator 判定主体是否为超级管理员（§7.3）。
// 仍受账号状态约束（checker）；此处独立判定，不经过缓存。
func (s *AuthorizationService) IsSuperAdministrator(ctx context.Context, ac AuthorizationContext) (bool, error) {
	if err := s.validateAC(ac); err != nil {
		return false, err
	}
	ctx = ContextWithTenant(ctx, ac.TenantID)
	if s.checker != nil {
		active, err := s.checker.IsSubjectActive(ctx, ac.SubjectID)
		if err != nil {
			return false, fmt.Errorf("rbac: subject status check failed (fail closed): %w", err)
		}
		if !active {
			return false, ErrSubjectInactive
		}
	}
	ok, err := s.repo.HasBuiltinSuperAdminRole(ctx, ac.SubjectID.String())
	if err != nil {
		return false, fmt.Errorf("rbac: check super administrator: %w", err)
	}
	return ok, nil
}

// ---- 失效操作（§6.3 失效矩阵） ----
// 授权域取自 ctx 租户槽位（服务层写路径已注入 operator 的授权域；
// 缺槽位时回落 default 域）。缓存 key 与读取路径的 ac.Scope() 保持同域。

// scopeOf 从 ctx 推导授权域（§6.1 scope 槽位），与 AuthorizationContext.Scope
// 一致地规范化租户大小写。
func scopeOf(ctx context.Context) string {
	if tenant, ok := TenantFromContext(ctx); ok && tenant != "" {
		return strings.ToLower(tenant)
	}
	return DefaultScope
}

// IncrSubjectVersion 递增主体权限版本号（精确级失效）。
// 适用：用户角色变更、用户额外授权 / 撤销 / 到期。
// 调用时机：数据库事务提交成功之后（§6.2 不变性）。
// 失败时管理接口应报错而非静默吞掉（§6.6）。
func (s *AuthorizationService) SyncSubjectVersion(ctx context.Context, subjectID SubjectID) error {
	atomic.AddInt64(&s.inv.attempts, 1)
	scope := scopeOf(ctx)
	subject := subjectID.String()
	// 权威版本已在变更事务内递增；此处同步副本 = 读权威真值 + 单调写回
	// （SetIntMax）。禁止 INCR：相对递增在副本被删后会从 1 重建，与权威值
	// 产生持久偏差且读者无法察觉（外部审核第四轮 P0-1 的并发场景）。
	// 任何一步失败 → 删除副本，迫使读路径回退 DB 权威值。
	version, err := s.counters.Get(ctx, dbSubjectVersionKey(scope, subject))
	if err != nil {
		atomic.AddInt64(&s.inv.failures, 1)
		_ = s.cch.Delete(ctx, subjectVersionKey(scope, subject))
		return err
	}
	if err := s.cch.SetIntMax(ctx, subjectVersionKey(scope, subject), version); err != nil {
		atomic.AddInt64(&s.inv.failures, 1)
		_ = s.cch.Delete(ctx, subjectVersionKey(scope, subject))
		return err
	}
	return nil
}

// IncrSubjectVersions 批量递增（角色权限变更 / 角色禁用的 fan-out，§6.3）。
// 任一失败即返回错误，调用方可据此对管理接口整体报错。
func (s *AuthorizationService) SyncSubjectVersions(ctx context.Context, subjectIDs []string) error {
	for _, id := range subjectIDs {
		if err := s.SyncSubjectVersion(ctx, SubjectID(id)); err != nil {
			return fmt.Errorf("rbac: invalidate subject %s: %w", id, err)
		}
	}
	return nil
}

// SyncGlobalEpoch 同步全局（跨租户）epoch 副本。适用：权限表（全局定义）的
// 状态变更与权限同步——单租户域 epoch 无法让其它租户的旧生成键失效。
func (s *AuthorizationService) SyncGlobalEpoch(ctx context.Context) error {
	atomic.AddInt64(&s.inv.attempts, 1)
	global, err := s.counters.Get(ctx, repository.GlobalEpochKey)
	if err != nil {
		atomic.AddInt64(&s.inv.failures, 1)
		_ = s.cch.Delete(ctx, globalEpochKey())
		return err
	}
	if err := s.cch.SetIntMax(ctx, globalEpochKey(), global); err != nil {
		atomic.AddInt64(&s.inv.failures, 1)
		_ = s.cch.Delete(ctx, globalEpochKey())
		return err
	}
	return nil
}

// IncrEpoch 递增当前授权域的全局 epoch（粗糙级失效）。
// 适用：权限禁用等低频全局事件——一次性使该域全部旧生成键不可达，
// 代价是全员冷启动一次（§6.3）。
func (s *AuthorizationService) SyncEpoch(ctx context.Context) error {
	atomic.AddInt64(&s.inv.attempts, 1)
	scope := scopeOf(ctx)
	// 重建碰撞防护（§6.2，同 IncrSubjectVersion 的 DEL 兜底但影响面是全域）：
	// epoch 键被淘汰后 INCR-from-missing 会重建为 1，与历史 epoch=1 时代的
	// (1, vN) 生成键碰撞且读者信任"在场"计数器——先 SETNX 探测，新建即
	// 清洗该域全部权限条目，再递增。清洗本身就是一次额外失效，语义安全。
	// 同 SyncSubjectVersion：读权威真值 + SetIntMax 单调写回；失败删副本。
	epoch, err := s.counters.Get(ctx, dbEpochKey(scope))
	if err != nil {
		atomic.AddInt64(&s.inv.failures, 1)
		_ = s.cch.Delete(ctx, epochKey(scope))
		return err
	}
	if err := s.cch.SetIntMax(ctx, epochKey(scope), epoch); err != nil {
		atomic.AddInt64(&s.inv.failures, 1)
		_ = s.cch.Delete(ctx, epochKey(scope))
		return err
	}
	return nil
}
