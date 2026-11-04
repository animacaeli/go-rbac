package core

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/animacaeli/go-rbac/cache"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/repository"
)

// AuthorizationService 实现 Authorizer（§4.3），并承担缓存 key 构造与失效。
//
// 读取路径（§6.2 的 Phase 1 形态，NoopCache 默认即每次回源数据库）：
//  1. 校验 AuthorizationContext（v1：TenantID 必须为空，fail closed）
//  2. （若注入）账号状态检查：false → ErrSubjectInactive；error → fail closed
//  3. 超级管理员判定：Has* 恒真；GetPermissions 返回空集合（§4.3，不引入通配符语义）
//  4. 缓存读取 → 未命中回源数据库聚合（角色权限并集 ∪ 额外授权）
//  5. 写回缓存：TTL 不超过最近一条临时授权的到期时间（§6.5）
//
// Phase 2 将引入版本号 + epoch 两级失效（§6.1/§6.3）；当前失效策略为
// 授权变更后按主体精确删除缓存 key（NoopCache 下为空操作）。
type AuthorizationService struct {
	repo    repository.AuthorizationRepo
	cch     cache.PermissionCache
	checker SubjectStatusChecker
	metrics Metrics
	ttl     time.Duration
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

// load 装载主体的有效授权状态（§6.2 读流程）。
func (s *AuthorizationService) load(ctx context.Context, ac AuthorizationContext) (loaded, error) {
	start := time.Now()
	cacheHit := false
	defer func() {
		s.metrics.AuthorizeObserved(cacheHit, time.Since(start))
	}()

	if err := ac.Validate(model.SubjectIDMaxLength); err != nil {
		return loaded{}, err
	}

	if s.checker != nil {
		active, err := s.checker.IsSubjectActive(ctx, ac.SubjectID)
		if err != nil {
			return loaded{}, fmt.Errorf("rbac: subject status check failed (fail closed): %w", err)
		}
		if !active {
			return loaded{}, ErrSubjectInactive
		}
	}

	isSuper, err := s.repo.HasBuiltinSuperAdminRole(ctx, ac.SubjectID.String())
	if err != nil {
		return loaded{}, fmt.Errorf("rbac: check super administrator: %w", err)
	}
	if isSuper {
		// 超管不走缓存：Has* 恒真、GetPermissions 空集合，无聚合可缓存。
		return loaded{permissions: map[string]struct{}{}, isSuper: true}, nil
	}

	key := s.subjectKey(ac)
	if cached, ok, err := s.cch.Get(ctx, key); err == nil && ok {
		cacheHit = true
		set := make(map[string]struct{}, len(cached))
		for _, code := range cached {
			set[code] = struct{}{}
		}
		return loaded{permissions: set}, nil
	}
	// 缓存未命中或故障（§6.6：故障时回源数据库，不信任旧缓存）——继续走数据库。

	now := time.Now().UTC()
	rolePerms, err := s.repo.EffectiveRolePermissions(ctx, ac.SubjectID.String())
	if err != nil {
		return loaded{}, fmt.Errorf("rbac: load role permissions: %w", err)
	}
	grantPerms, err := s.repo.EffectiveGrantPermissions(ctx, ac.SubjectID.String(), now)
	if err != nil {
		return loaded{}, fmt.Errorf("rbac: load grant permissions: %w", err)
	}

	set := make(map[string]struct{}, len(rolePerms)+len(grantPerms))
	cached := make([]string, 0, len(rolePerms)+len(grantPerms))
	for _, code := range rolePerms {
		if _, dup := set[code]; !dup {
			set[code] = struct{}{}
			cached = append(cached, code)
		}
	}
	for _, code := range grantPerms {
		if _, dup := set[code]; !dup {
			set[code] = struct{}{}
			cached = append(cached, code)
		}
	}

	// 写回缓存：TTL 以最近一条临时授权到期时间为上限（§6.5）。
	ttl := s.ttl
	if nearest, err := s.repo.NearestGrantExpiry(ctx, ac.SubjectID.String(), now); err == nil && nearest != nil {
		if bounded := nearest.Sub(now); bounded > 0 && bounded < ttl {
			ttl = bounded
		}
	}
	// 缓存写失败不影响鉴权结果（下次回源即可）。
	_ = s.cch.Set(ctx, key, cached, ttl)

	return loaded{permissions: set}, nil
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
// 仍受账号状态约束（checker 在 load 内执行）；此处独立判定。
func (s *AuthorizationService) IsSuperAdministrator(ctx context.Context, ac AuthorizationContext) (bool, error) {
	if err := ac.Validate(model.SubjectIDMaxLength); err != nil {
		return false, err
	}
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

// ---- 缓存失效（Phase 1：按主体精确删除；NoopCache 下为空操作） ----

// permKeyPrefix 与 §6.1 key 形状一致；Phase 2 引入版本号后 key 追加 :v{version}。
const permKeyPrefix = "rbac"

func (s *AuthorizationService) subjectKey(ac AuthorizationContext) string {
	return permKeyPrefix + ":" + ac.Scope() + ":subject:" + ac.SubjectID.String() + ":perm"
}

// InvalidateSubject 删除单个主体的权限缓存。授权变更后必须调用（§6.3）；
// 失败时管理接口应报错而非静默吞掉（§6.6）。
func (s *AuthorizationService) InvalidateSubject(ctx context.Context, subjectID SubjectID) error {
	key := permKeyPrefix + ":" + DefaultScope + ":subject:" + subjectID.String() + ":perm"
	return s.cch.Delete(ctx, key)
}

// InvalidateSubjects 批量删除主体缓存（角色权限变更的 fan-out，§6.3）。
// 任一失败即返回错误，调用方可据此对管理接口整体报错。
func (s *AuthorizationService) InvalidateSubjects(ctx context.Context, subjectIDs []string) error {
	for _, id := range subjectIDs {
		if err := s.InvalidateSubject(ctx, SubjectID(id)); err != nil {
			return fmt.Errorf("rbac: invalidate subject %s: %w", id, err)
		}
	}
	return nil
}
