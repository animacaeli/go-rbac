package rbac

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/animacaeli/go-rbac/cache"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/migrations"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/animacaeli/go-rbac/repository"
	gormrepo "github.com/animacaeli/go-rbac/repository/gormrepo"
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
		return nil, DBRequiredError
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}

	// 内置 rbac:* 管理权限码自动并入注册中心（§4.7）。
	if err := cfg.reg.Register(registry.BuiltinPermissions()...); err != nil {
		return nil, fmt.Errorf("rbac: register builtin permissions: %w", err)
	}

	repos := gormrepo.New(cfg.db).Assemble()

	authorizer := core.NewAuthorizationService(
		repos.Authorization, cfg.cch, cfg.statusChecker, cfg.metrics, cfg.cacheTTL,
	)

	deps := core.ServiceDeps{
		Roles:           repos.Roles,
		Permissions:     repos.Permissions,
		UserRoles:       repos.UserRoles,
		RolePermissions: repos.RolePermissions,
		Grants:          repos.Grants,
		Registry:        cfg.reg,
		Authorizer:      authorizer,
		GrantorMustHold: cfg.grantorMustHold,
	}

	app := &App{
		cfg:        cfg,
		repos:      repos,
		authorizer: authorizer,
		roles:      core.NewRoleService(deps),
		userRoles:  core.NewUserRoleService(deps),
		grants:     core.NewGrantService(deps),
	}

	// Module Registry：注册（无数据库副作用）+ 迁移收集（§3.3）。
	for _, mod := range cfg.modules {
		if mod.Name() == migrations.CoreModule {
			return nil, fmt.Errorf("rbac: module name %q is reserved", migrations.CoreModule)
		}
		if err := mod.Register(app); err != nil {
			return nil, fmt.Errorf("rbac: module %s register: %w", mod.Name(), err)
		}
		app.migrations = append(app.migrations, mod.Migrations()...)
	}

	return app, nil
}

// App 是 RBAC 应用的组装根：服务获取、迁移执行、权限同步。
type App struct {
	cfg        config
	repos      repository.Repos
	authorizer *core.AuthorizationService
	roles      *core.RoleService
	userRoles  *core.UserRoleService
	grants     *core.GrantService
	migrations []Migration
}

// Authorizer 返回统一授权服务（注入框架适配器）。
func (a *App) Authorizer() core.Authorizer { return a.authorizer }

// Roles 返回角色管理服务。
func (a *App) Roles() *core.RoleService { return a.roles }

// UserRoles 返回用户角色关联管理服务。
func (a *App) UserRoles() *core.UserRoleService { return a.userRoles }

// Grants 返回用户额外授权管理服务。
func (a *App) Grants() *core.GrantService { return a.grants }

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

// SyncPermissions 将注册中心同步至数据库（§2.3），幂等可重复执行。
func (a *App) SyncPermissions(ctx context.Context) (registry.SyncResult, error) {
	return registry.Sync(ctx, a.cfg.reg, a.repos.Permissions)
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
// 注意：§11 将"超管种子初始化与配置细节"列为待细化项；v1 提供此最小契约。
func (a *App) SeedSuperAdmin(ctx context.Context, subjectID string) error {
	if subjectID == "" || len(subjectID) > model.SubjectIDMaxLength {
		return fmt.Errorf("%w: %q", core.ErrInvalidSubjectID, subjectID)
	}
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
	return a.authorizer.InvalidateSubject(ctx, core.SubjectID(subjectID))
}
