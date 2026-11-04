// Package tenant 实现多租户隔离模块（§2.9）。
//
// 本模块承担（§2.9）：
//   - 租户上下文解析契约（TenantResolver，由业务实现）
//   - 迁移契约：加列 tenant_id（默认空串=default/平台域）→ 回填 → 重建三唯一键（§5.5，
//     第一验收项 = modules/tenant 集成测试的迁移契约用例）
//   - 数据库查询隔离：以租户隔离仓储替换内部仓储（App.ReplaceRepositories），
//     三张租户归属表（rbac_roles / rbac_user_roles / rbac_user_grants）的读写
//     全部按 ctx 中的租户过滤；权限与角色权限定义为全局，不隔离
//   - 缓存隔离：缓存 key 的 scope 槽位自 Phase 1 起即按授权域构造（§6.1），
//     启用本模块后 AuthorizationContext.TenantID 必须提供，缺失即 fail closed
//   - 跨租户授权保护：角色引用校验归属、聚合查询按租户过滤、授权者持权
//     约束在租户域内判定——结构性阻止跨租户提权
//
// 语义决策（模块内部设计，§2.9 授权本阶段确定）：
//   - 平台域 = tenant_id ”（单租户模式即平台域）；平台超管经 SeedSuperAdmin
//     种子于平台域，对全部租户生效（超管判定匹配本域或平台域的内置角色）
//   - 租户级超管经 SeedSuperAdminInTenant 种子于对应租户，仅在本域生效
//   - 角色归属其创建域；用户角色绑定与额外授权必须与角色同域（Assign 时校验）
//   - 主体是否可属多租户：同一 subject_id 可出现在多个租户域（授权域隔离，
//     业务侧身份体系自行决定映射）；平台级角色的表达：平台域中的普通角色
//
// 用法：
//
//	tenantMod := tenant.New()
//	app, _ := rbac.New(
//	    rbac.WithDB(db),
//	    rbac.WithPermissionRegistry(reg),
//	    rbac.WithModules(tenantMod), // 建议注册在首位（迁移按注册顺序执行，租户契约先行）
//	)
//	// 请求入口（中间件）：从可信上下文解析租户并注入
//	ctx = core.ContextWithTenant(ctx, tenantID)
//	// 租户超管种子
//	_ = tenantMod.SeedSuperAdminInTenant(ctx, "acme", "10001")
package tenant

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/core"
	gormrepo "github.com/animacaeli/go-rbac/internal/repository/gormrepo"
	"github.com/animacaeli/go-rbac/migrations"
	"github.com/animacaeli/go-rbac/model"
	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var tenantFS embed.FS

// TenantIDMaxLength 与迁移契约的列宽一致。
const TenantIDMaxLength = 64

// errScopeMissing 表示 ctx 缺少租户槽位——fail closed（§2.9）。
var errScopeMissing = errors.New("rbac/modules/tenant: tenant scope missing in context (inject via core.ContextWithTenant; fail closed)")

// TenantResolver 由业务项目实现：从已完成认证的可信上下文解析租户标识
// （规则同 SubjectResolver，§4.4）。解析失败必须返回错误，不得回退默认域。
type TenantResolver interface {
	ResolveTenant(ctx context.Context) (string, error)
}

// Module 是多租户模块（实现 rbac.Module）。
type Module struct {
	db    *gorm.DB
	repos *Repos
}

var _ rbac.Module = (*Module)(nil)

// New 构造多租户模块。
func New() *Module { return &Module{} }

// Name 返回模块名。
func (m *Module) Name() string { return "tenant" }

// Register 以租户隔离仓储替换内部仓储并启用租户校验策略。
// 只做装配，不触库（迁移由业务显式触发，§3.3/§4.1）。
func (m *Module) Register(app *rbac.App) error {
	m.db = app.DB()
	base := gormrepo.New(app.DB()).Assemble()
	m.repos = newRepos(base, app.DB())
	app.ReplaceRepositories(m.repos.Assemble())
	app.EnableTenantScope()
	return nil
}

// Migrations 返回迁移契约（§5.5）。
func (m *Module) Migrations() []rbac.Migration {
	data, err := tenantFS.ReadFile("migrations/0001_tenant.sql")
	if err != nil {
		panic(fmt.Sprintf("rbac/modules/tenant: read embedded migration: %v", err))
	}
	return []rbac.Migration{
		{Module: m.Name(), Version: "0001", Name: "tenant_columns_and_keys", SQL: string(data)},
	}
}

// SeedSuperAdminInTenant 在指定租户内创建内置超管角色（幂等）并绑定主体。
// 租户级超管仅在本域生效（§2.9 平台/租户边界）。
func (m *Module) SeedSuperAdminInTenant(ctx context.Context, tenantID, subjectID string) error {
	if tenantID == "" || len(tenantID) > TenantIDMaxLength {
		return fmt.Errorf("rbac/modules/tenant: invalid tenant id %q", tenantID)
	}
	if subjectID == "" || len(subjectID) > model.SubjectIDMaxLength {
		return fmt.Errorf("%w: %q", core.ErrInvalidSubjectID, subjectID)
	}
	ctx = core.ContextWithTenant(ctx, tenantID)

	roleID, err := m.ensureBuiltinRole(ctx, tenantID)
	if err != nil {
		return err
	}
	return m.db.WithContext(ctx).Exec(
		"INSERT IGNORE INTO rbac_user_roles (tenant_id, subject_id, role_id, created_at) VALUES (?, ?, ?, UTC_TIMESTAMP(3))",
		tenantID, subjectID, roleID,
	).Error
}

// ensureBuiltinRole 确保指定租户存在内置超管角色，返回角色 ID。
func (m *Module) ensureBuiltinRole(ctx context.Context, tenantID string) (uint64, error) {
	var id uint64
	err := m.db.WithContext(ctx).
		Table("rbac_roles").
		Select("id").
		Where("tenant_id = ? AND code = ? AND is_builtin = ?", tenantID, model.BuiltinSuperAdminRoleCode, true).
		Scan(&id).Error
	if err != nil {
		return 0, err
	}
	if id > 0 {
		return id, nil
	}
	// INSERT IGNORE：并发种子时唯一键 (tenant_id, code) 冲突静默幂等。
	if err := m.db.WithContext(ctx).Exec(
		"INSERT IGNORE INTO rbac_roles (tenant_id, code, name, description, is_builtin, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))",
		tenantID, model.BuiltinSuperAdminRoleCode,
		"超级管理员（租户）", "内置受保护角色：租户级超级管理员载体",
		true, model.RoleStatusEnabled,
	).Error; err != nil {
		return 0, fmt.Errorf("rbac/modules/tenant: seed tenant super admin role: %w", err)
	}
	err = m.db.WithContext(ctx).
		Table("rbac_roles").
		Select("id").
		Where("tenant_id = ? AND code = ?", tenantID, model.BuiltinSuperAdminRoleCode).
		Scan(&id).Error
	if err != nil || id == 0 {
		return 0, fmt.Errorf("rbac/modules/tenant: seed tenant super admin role: readback failed: %v", err)
	}
	return id, nil
}

// TenantOf 验证租户标识格式。
func TenantOf(tenantID string) error {
	if tenantID == "" || len(tenantID) > TenantIDMaxLength {
		return fmt.Errorf("rbac/modules/tenant: invalid tenant id %q", tenantID)
	}
	return nil
}

// 编译期确认模块迁移的 Module 键不与 Core 冲突。
var _ = migrations.CoreModule
