package core

import (
	"context"
	"fmt"
	"sort"
	"strconv"
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
	repo    repository.AuthorizationRepo
	cch     cache.PermissionCache
	checker SubjectStatusChecker
	metrics Metrics
	ttl     time.Duration
	sf      singleflight.Group

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
	} else if ac.TenantID != "" {
		return ErrTenantNotSupported
	}
	return nil
}

var _ Authorizer = (*AuthorizationService)(nil)

// NewAuthorizationService 构造授权服务。ttl <= 0 时默认 5 分钟。
func NewAuthorizationService(
	repo repository.AuthorizationRepo,
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
	return &AuthorizationService{repo: repo, cch: cch, checker: checker, metrics: metrics, ttl: ttl}
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

func subjectVersionKey(scope, subjectID string) string {
	return "rbac:" + scope + ":subject:" + subjectID + ":version"
}

func subjectPermKey(scope, subjectID string, gen int64) string {
	return "rbac:" + scope + ":subject:" + subjectID + ":perm:v" + strconv.FormatInt(gen, 10)
}

// generationKey 合并 epoch 与主体版本号为单个生成键。
// counter 使用低 32 位（现实中不可能触达），epoch 占高位；
// 任一递增都会改变生成键，使旧 perm key 不可达。
func generationKey(epoch, subjectVersion int64) int64 {
	return epoch<<32 | subjectVersion
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

	// 生成键基线协议（§6.2 / §6.1）：
	//   - 计数器读取失败（含值损坏）→ 缓存状态不可信：回源数据库且不写回（§6.6）；
	//   - 计数器缺失（首写前或被淘汰）→ 不读权限缓存，进 flight 建立基线后再写；
	//     使"计数器被淘汰"不可能命中旧生成键下已撤销的权限集合
	//     （版本号只允许落后于数据、永不允许回退——键丢失即回退，必须旁路）。
	epoch, epochOK, err := s.cch.GetInt(ctx, epochKey(scope))
	if err != nil {
		set, isSuper, err := s.loadFromDB(ctx, ac)
		return loaded{permissions: set, isSuper: isSuper}, false, false, err
	}
	version, versionOK, err := s.cch.GetInt(ctx, subjectVersionKey(scope, subject))
	if err != nil {
		set, isSuper, err := s.loadFromDB(ctx, ac)
		return loaded{permissions: set, isSuper: isSuper}, false, false, err
	}

	var refGen int64
	trusted := epochOK && versionOK
	if trusted {
		refGen = generationKey(epoch, version)
		if cached, ok, err := s.cch.Get(ctx, subjectPermKey(scope, subject, refGen)); err == nil && ok {
			return parseCached(cached), true, false, nil
		}
	}
	// 未命中 / 计数器缺失 / 故障 → singleflight 合并回源（§6.8）。
	v, err, _ := s.sf.Do(scope+"/"+subject, func() (any, error) {
		return s.aggregateAndCache(ctx, ac, refGen, trusted)
	})
	if err != nil {
		return loaded{}, false, false, err
	}
	result := v.(aggregateResult)
	return loaded{permissions: result.set, isSuper: result.isSuper}, false, result.unstable, nil
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

// aggregateAndCache 在 singleflight 内执行：建立计数器基线（缺失时）→
// 读取当前生成键 → 二次探测缓存 → 数据库聚合 → 复核生成键未变 → 写回。
// refGen 为外层快路径读到的参考生成键；trusted=false 表示外层计数器缺失
// （首写或被淘汰），此时没有可信参考，flight 以自建基线后的生成键为准。
func (s *AuthorizationService) aggregateAndCache(ctx context.Context, ac AuthorizationContext, refGen int64, trusted bool) (aggregateResult, error) {
	scope := ac.Scope()
	subject := ac.SubjectID.String()

	// 基线协议（§6.2）：缺失的计数器 SETNX 0 重建；若为新建（键曾丢失），
	// 重建值可能与历史生成键碰撞——必须先清洗受影响的权限条目，再继续。
	if err := s.ensureCounters(ctx, scope, subject); err != nil {
		// 无法建立基线 → 数据库聚合但不写回（§6.6）。
		return s.aggregateUncached(ctx, ac)
	}
	gen, ok, err := s.readGeneration(ctx, scope, subject)
	if err != nil || !ok {
		return s.aggregateUncached(ctx, ac)
	}
	if trusted && gen != refGen {
		// 外层读取后已发生变更 → 丢弃重走流程（§6.2 第 5 步）。
		set, _, _, aggErr := s.aggregate(ctx, ac, time.Now().UTC())
		if aggErr != nil {
			return aggregateResult{}, aggErr
		}
		return aggregateResult{set: set, unstable: true}, nil
	}

	if cached, hit, err := s.cch.Get(ctx, subjectPermKey(scope, subject, gen)); err == nil && hit {
		l := parseCached(cached)
		return aggregateResult{set: l.permissions, isSuper: l.isSuper}, nil
	}

	isSuper, err := s.repo.HasBuiltinSuperAdminRole(ctx, subject)
	if err != nil {
		return aggregateResult{}, fmt.Errorf("rbac: check super administrator: %w", err)
	}
	if isSuper {
		// 超管：缓存哨兵集合（TTL 走默认值），Has* 恒真、GetPermissions 空集合。
		_ = s.cch.Set(ctx, subjectPermKey(scope, subject, gen), []string{superAdminSentinel}, s.ttl)
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

	// 写回前复核生成键（§6.2 第 5 步 / §6.4 写前复核）。
	gen2, ok, err := s.readGeneration(ctx, scope, subject)
	if err != nil || !ok || gen2 != gen {
		return aggregateResult{set: set}, nil // 无法复核 / 已变 → 数据有效但不写回
	}

	ttl := s.ttl
	if nearest != nil {
		if bounded := nearest.Sub(now); bounded > 0 && bounded < ttl {
			ttl = bounded
		}
	}
	// 缓存写失败不影响本次鉴权结果（下次回源即可）。
	_ = s.cch.Set(ctx, subjectPermKey(scope, subject, gen), flatten(set), ttl)
	return aggregateResult{set: set}, nil
}

// ensureCounters 对缺失的计数器建立 0 基线（SETNX）。
// 新建（键曾丢失）即触发清洗：
//   - epoch 新建 → 该授权域全部权限条目失效（全局生成键不可信）；
//   - version 新建 → 该主体权限条目失效。
//
// 清洗使重建后的生成键命名空间从零开始，历史陈旧条目不可达。
// 已知残余窗口：SETNX 与清洗完成之间，并发读者可能读到陈旧条目
// （毫秒级，需在计数器被淘汰后恰好发生；运维上以 volatile-*/noeviction
// 淘汰策略使计数器（唯一无 TTL 键族）不可淘汰为第一道防线）。
func (s *AuthorizationService) ensureCounters(ctx context.Context, scope, subject string) error {
	epochCreated, err := s.cch.InitCounter(ctx, epochKey(scope))
	if err != nil {
		return err
	}
	if epochCreated {
		if err := s.cch.DeleteByPattern(ctx, "rbac:"+scope+":subject:*:perm:*"); err != nil {
			return err
		}
	}
	versionCreated, err := s.cch.InitCounter(ctx, subjectVersionKey(scope, subject))
	if err != nil {
		return err
	}
	if versionCreated {
		if err := s.cch.DeleteByPattern(ctx, "rbac:"+scope+":subject:"+subject+":perm:*"); err != nil {
			return err
		}
	}
	return nil
}

// readGeneration 读取当前生成键；ok=false 表示计数器缺失（不可信）。
func (s *AuthorizationService) readGeneration(ctx context.Context, scope, subject string) (int64, bool, error) {
	epoch, epochOK, err := s.cch.GetInt(ctx, epochKey(scope))
	if err != nil || !epochOK {
		return 0, false, err
	}
	version, versionOK, err := s.cch.GetInt(ctx, subjectVersionKey(scope, subject))
	if err != nil || !versionOK {
		return 0, false, err
	}
	return generationKey(epoch, version), true, nil
}

// aggregateUncached 聚合数据库且不读写缓存。
func (s *AuthorizationService) aggregateUncached(ctx context.Context, ac AuthorizationContext) (aggregateResult, error) {
	set, isSuper, err := s.loadFromDB(ctx, ac)
	if err != nil {
		return aggregateResult{}, err
	}
	return aggregateResult{set: set, isSuper: isSuper}, nil
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

// scopeOf 从 ctx 推导授权域（§6.1 scope 槽位）。
func scopeOf(ctx context.Context) string {
	if tenant, ok := TenantFromContext(ctx); ok && tenant != "" {
		return tenant
	}
	return DefaultScope
}

// IncrSubjectVersion 递增主体权限版本号（精确级失效）。
// 适用：用户角色变更、用户额外授权 / 撤销 / 到期。
// 调用时机：数据库事务提交成功之后（§6.2 不变性）。
// 失败时管理接口应报错而非静默吞掉（§6.6）。
func (s *AuthorizationService) IncrSubjectVersion(ctx context.Context, subjectID SubjectID) error {
	atomic.AddInt64(&s.inv.attempts, 1)
	scope := scopeOf(ctx)
	subject := subjectID.String()
	newVersion, err := s.cch.Incr(ctx, subjectVersionKey(scope, subject))
	if err != nil {
		atomic.AddInt64(&s.inv.failures, 1)
		return err
	}
	// 自愈双保险（§6.2）：删除新生成键上的旧条目——正常情况下该键本就
	// 即将失效；异常情况下（计数器曾被淘汰后 INCR-from-missing 复位到 1，
	// 与历史版本 1 的生成键碰撞）这恰好清掉可能复活的旧权限集合。
	epoch, ok, err := s.cch.GetInt(ctx, epochKey(scope))
	if err == nil && ok {
		_ = s.cch.Delete(ctx, subjectPermKey(scope, subject, generationKey(epoch, newVersion)))
	}
	return nil
}

// IncrSubjectVersions 批量递增（角色权限变更 / 角色禁用的 fan-out，§6.3）。
// 任一失败即返回错误，调用方可据此对管理接口整体报错。
func (s *AuthorizationService) IncrSubjectVersions(ctx context.Context, subjectIDs []string) error {
	for _, id := range subjectIDs {
		if err := s.IncrSubjectVersion(ctx, SubjectID(id)); err != nil {
			return fmt.Errorf("rbac: invalidate subject %s: %w", id, err)
		}
	}
	return nil
}

// IncrEpoch 递增当前授权域的全局 epoch（粗糙级失效）。
// 适用：权限禁用等低频全局事件——一次性使该域全部旧生成键不可达，
// 代价是全员冷启动一次（§6.3）。
func (s *AuthorizationService) IncrEpoch(ctx context.Context) error {
	atomic.AddInt64(&s.inv.attempts, 1)
	scope := scopeOf(ctx)
	// 重建碰撞防护（§6.2，同 IncrSubjectVersion 的 DEL 兜底但影响面是全域）：
	// epoch 键被淘汰后 INCR-from-missing 会重建为 1，与历史 epoch=1 时代的
	// (1, vN) 生成键碰撞且读者信任"在场"计数器——先 SETNX 探测，新建即
	// 清洗该域全部权限条目，再递增。清洗本身就是一次额外失效，语义安全。
	created, err := s.cch.InitCounter(ctx, epochKey(scope))
	if err != nil {
		atomic.AddInt64(&s.inv.failures, 1)
		return err
	}
	if created {
		if err := s.cch.DeleteByPattern(ctx, "rbac:"+scope+":subject:*:perm:*"); err != nil {
			atomic.AddInt64(&s.inv.failures, 1)
			return err
		}
	}
	if _, err := s.cch.Incr(ctx, epochKey(scope)); err != nil {
		atomic.AddInt64(&s.inv.failures, 1)
		return err
	}
	return nil
}
