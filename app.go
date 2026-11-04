package rbac

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/animacaeli/go-rbac/cache"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/internal/repository"
	gormrepo "github.com/animacaeli/go-rbac/internal/repository/gormrepo"
	"github.com/animacaeli/go-rbac/migrations"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
	"gorm.io/gorm"
)

// New 组装 RBAC 应用（§4.1）。只做组装与依赖检查：
// 不执行迁移、不触库、无副作用。
func New(opts ...Option) (*App, error) {
	cfg := config{
		cch:             cache.NoopCache{},
		reg:             registry.NewRegistry(),
		metrics:         core.NoopMetrics{},
		grantorMustHold: true,
		cacheTTL:        5 * time.Minute,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.db == nil {
		return nil, ErrDBRequired
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}
	// 配置校验（公共库把配置错误转为明确错误而非运行时 panic）。
	if cfg.reg == nil {
		return nil, fmt.Errorf("%w: permission registry is nil", ErrInvalidOption)
	}
	if cfg.cacheTTL < 0 {
		return nil, fmt.Errorf("%w: negative cache TTL %s", ErrInvalidOption, cfg.cacheTTL)
	}
	mods, err := resolveModules(cfg.modules)
	if err != nil {
		return nil, err
	}

	// 内置 rbac:* 管理权限码自动并入注册中心（§4.7）。
	if err := cfg.reg.Register(registry.BuiltinPermissions()...); err != nil {
		return nil, fmt.Errorf("rbac: register builtin permissions: %w", err)
	}

	repos := gormrepo.New(cfg.db).Assemble()

	events := core.NewEventBus()
	if cfg.eventSink != nil {
		events.SetSink(cfg.eventSink)
	}

	app := &App{cfg: cfg, repos: repos, events: events}
	app.rebuildServices()

	// Module Registry：依赖拓扑序注册（无数据库副作用）+ 迁移收集（§3.3）。
	for _, mod := range mods {
		if err := mod.Register(app); err != nil {
			return nil, fmt.Errorf("rbac: module %s register: %w", mod.Name(), err)
		}
		app.migrations = append(app.migrations, mod.Migrations()...)
	}

	return app, nil
}

// rebuildServices 以当前 repos 与配置重建授权服务与管理服务。
// 模块（如 tenant）在 Register 期替换仓储后调用。
func (a *App) rebuildServices() {
	authorizer := core.NewAuthorizationService(
		a.repos.Authorization, a.cfg.cch, a.cfg.statusChecker, a.cfg.metrics, a.cfg.cacheTTL,
	)
	authorizer.SetTenantScopeRequired(a.tenantScope)
	a.authorizer = authorizer

	deps := core.ServiceDeps{
		Roles:           a.repos.Roles,
		Permissions:     a.repos.Permissions,
		UserRoles:       a.repos.UserRoles,
		RolePermissions: a.repos.RolePermissions,
		Grants:          a.repos.Grants,
		Registry:        a.cfg.reg,
		Authorizer:      authorizer,
		Events:          a.events,
		GrantorMustHold: a.cfg.grantorMustHold,
	}
	a.roles = core.NewRoleService(deps)
	a.userRoles = core.NewUserRoleService(deps)
	a.grants = core.NewGrantService(deps)
	a.permissions = core.NewPermissionService(deps)
}

// App 是 RBAC 应用的组装根：服务获取、迁移执行、权限同步。
type App struct {
	cfg         config
	repos       repository.Repos
	authorizer  *core.AuthorizationService
	events      *core.EventBus
	tenantScope bool
	roles       *core.RoleService
	userRoles   *core.UserRoleService
	grants      *core.GrantService
	permissions *core.PermissionService
	migrations  []Migration
}

// Authorizer 返回统一授权服务（注入框架适配器）。
func (a *App) Authorizer() core.Authorizer { return a.authorizer }

// Roles 返回角色管理服务。
func (a *App) Roles() *core.RoleService { return a.roles }

// UserRoles 返回用户角色关联管理服务。
func (a *App) UserRoles() *core.UserRoleService { return a.userRoles }

// Grants 返回用户额外授权管理服务。
func (a *App) Grants() *core.GrantService { return a.grants }

// PermissionsRepository 暴露内部权限仓储（扩展模块装配用；§3.4：内部 API，
// 不承诺跨版本兼容）。
func (a *App) PermissionsRepository() repository.PermissionRepo { return a.repos.Permissions }

// Permissions 返回权限资源管理服务（状态控制与查询）。
func (a *App) Permissions() *core.PermissionService { return a.permissions }

// EnableTenantScope 启用多租户校验策略：AuthorizationContext.TenantID 从
// "必须为空"变为"必须提供"（缺失即 fail closed，§2.9）。由 tenant 模块在
// Register 期调用；亦可由业务项目在组装后、服务使用前手动调用。
func (a *App) EnableTenantScope() {
	a.tenantScope = true
	a.authorizer.SetTenantScopeRequired(true)
}

// ReplaceRepositories 以租户隔离仓储替换内部仓储并重建服务。
// 仅供扩展模块（tenant）在 Register 期使用（§3.4：内部 API，不承诺兼容）。
// 调用后 App 的 Authorizer 与管理服务全部切换到新仓储；缓存与事件配置保留。
func (a *App) ReplaceRepositories(repos repository.Repos) {
	a.repos = repos
	a.rebuildServices()
}

// CacheDiagnostics 探测缓存一致性状态（运行模式 / 计数器 / 生成键 / 失效计数）。
// Simple 模式（NoopCache）同样可用（返回 mode=simple 与零值计数器）。
func (a *App) CacheDiagnostics(ctx context.Context, ac core.AuthorizationContext) (core.CacheDiagnostics, error) {
	return a.authorizer.DiagnoseCache(ctx, ac)
}

// SetEventSink 注入授权变更事件实现（Audit 模块在 Register 时调用，
// 业务项目也可经 WithEventSink 在组装期注入）。
func (a *App) SetEventSink(sink core.EventSink) { a.events.SetSink(sink) }

// Registry 返回权限注册中心（含内置 rbac:* 权限码）。
func (a *App) Registry() *registry.Registry { return a.cfg.reg }

// DB 返回底层 GORM 句柄（供业务项目复用连接，勿用于绕过 RBAC 修改权限数据）。
func (a *App) DB() *gorm.DB { return a.cfg.db }

// Migrate 执行数据库迁移（§5.7）：Core → 模块注册顺序，幂等。
// 显式触发：New 不执行迁移；生产环境建议在发布流程统一执行。
func (a *App) Migrate(ctx context.Context) error {
	all := append([]Migration{}, migrations.Core()...)
	all = append(all, a.migrations...)
	return migrations.Apply(ctx, a.cfg.db, all)
}

// SyncPermissions 将注册中心同步至数据库（§2.3），幂等可重复执行：
// registry.Diff 计算差量计划，仓储在单事务内应用。
// 同步后递增全局 epoch：废弃/恢复启用直接影响全体读者（§6.3 保守失效）。
func (a *App) SyncPermissions(ctx context.Context) (registry.SyncResult, error) {
	existing, err := a.repos.Permissions.ListAll(ctx)
	if err != nil {
		return registry.SyncResult{}, fmt.Errorf("rbac: sync load permissions: %w", err)
	}
	result, plan := registry.Diff(a.cfg.reg, existing)
	if plan.Changed() {
		if err := a.repos.Permissions.ApplySync(ctx, plan); err != nil {
			return result, fmt.Errorf("rbac: sync apply: %w", err)
		}
		if err := a.authorizer.IncrEpoch(ctx); err != nil {
			return result, fmt.Errorf("%w: %v", core.ErrInvalidationFailedAfterCommit, err)
		}
		_ = a.events.Record(ctx, core.NewEvent(core.EventPermissionsSynced,
			core.AuthorizationContext{}, "registry", map[string]string{
				"created":     strconv.Itoa(result.Created),
				"updated":     strconv.Itoa(result.Updated),
				"reactivated": strconv.Itoa(result.Reactivated),
				"deprecated":  strconv.Itoa(result.Deprecated),
			}))
	}
	return result, nil
}

// ValidatePermissionCodes 启动期权限码交叉校验（§2.6）：将路由或集中声明的
// 权限码清单与 Registry 比对，发现未注册权限码返回错误——调用方应在启动
// 阶段 fail fast（例如配合 ginadapter Guard.DeclaredCodes 使用）。
func (a *App) ValidatePermissionCodes(codes ...string) error {
	var unknown []string
	for _, c := range codes {
		if !a.cfg.reg.Has(c) {
			unknown = append(unknown, c)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("rbac: undeclared permission codes (typo or missing registration): %v", unknown)
	}
	return nil
}

// SeedSuperAdmin 初始化超级管理员（§7.3）：确保内置受保护角色存在，
// 并将给定主体绑定到该角色。这是唯一的超管授予入口——管理接口不可授予。
// 幂等：重复执行无害。主体绑定绕过管理服务的内置角色保护，属刻意设计。
//
// Security：本方法不鉴权调用者——只能用于可信的初始化流程（部署脚本、
// 初始化 Job），绝不可暴露给普通业务请求。
//
// 注意：§11 将"超管种子初始化与配置细节"列为待细化项；v1 提供此最小契约。
func (a *App) SeedSuperAdmin(ctx context.Context, subjectID string) error {
	if subjectID == "" || len(subjectID) > model.SubjectIDMaxLength {
		return fmt.Errorf("%w: %q", core.ErrInvalidSubjectID, subjectID)
	}
	// 超管种子固定写入平台域（tenant_id=''，§2.9 default 域），
	// 与租户模块的租户超管种子（SeedSuperAdminInTenant）区分。
	ctx = core.ContextWithTenant(ctx, "")
	role, err := a.repos.Roles.FindByCode(ctx, model.BuiltinSuperAdminRoleCode)
	if repository.IsNotFound(err) {
		role = &model.Role{
			Code:        model.BuiltinSuperAdminRoleCode,
			Name:        "超级管理员",
			Description: "内置受保护角色：超级管理员载体（不可经管理接口授予、撤销、删除、禁用）",
			IsBuiltin:   true,
			Status:      model.RoleStatusEnabled,
		}
		if err := a.repos.Roles.Create(ctx, role); err != nil {
			return fmt.Errorf("rbac: seed super admin role: %w", err)
		}
	} else if err != nil {
		return err
	}
	if err := a.repos.UserRoles.Assign(ctx, subjectID, role.ID); err != nil {
		return fmt.Errorf("rbac: seed super admin subject: %w", err)
	}
	if err := a.authorizer.IncrSubjectVersion(ctx, core.SubjectID(subjectID)); err != nil {
		return fmt.Errorf("%w: %v", core.ErrInvalidationFailedAfterCommit, err)
	}
	return nil
}
