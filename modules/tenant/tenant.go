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
//     业务侧身份体系自行决定映射）
//   - 平台级角色的表达：**不支持**"平台域普通角色跨租户生效"——跨域角色引用
//     被结构性拒绝（避免租户静默继承平台权限）；需要跨租户权限时使用平台
//     超管（SeedSuperAdmin），或为每个租户分别建角色
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
	app   *rbac.App
}

var _ rbac.Module = (*Module)(nil)

// New 构造多租户模块。
func New() *Module { return &Module{} }

// Name 返回模块名。
func (m *Module) Name() string { return "tenant" }

// Dependencies 声明依赖的模块名（当前无模块间依赖）。
func (m *Module) Dependencies() []string { return nil }

// Register 以租户隔离仓储替换内部仓储并启用租户校验策略。
// 只做装配，不触库（迁移由业务显式触发，§3.3/§4.1）。
func (m *Module) Register(app *rbac.App) error {
	m.app = app
	m.db = app.DB()
	base := gormrepo.New(app.DB()).Assemble()
	m.repos = newRepos(base, app.DB())
	// 先打开租户策略再替换仓储：ReplaceRepositories 会重建管理服务，服务
	// 依赖里的 TenancyRequired 取自 App.tenantScope——顺序反了会让管理服务
	// 认为当前是单租户模式（operator 带租户反而被拒绝）。
	app.EnableTenantScope()
	app.ReplaceRepositories(m.repos.Assemble())
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
//
// Security：本方法不鉴权调用者，且直接绕过"内置角色不可经管理接口授予"
// 的保护——它只能用于可信的初始化流程（部署脚本、初始化 Job），
// 绝不可暴露给普通业务请求或管理 HTTP 接口。
func (m *Module) SeedSuperAdminInTenant(ctx context.Context, tenantID, subjectID string) error {
	if m.app == nil || m.repos == nil {
		return fmt.Errorf("rbac/modules/tenant: module not registered")
	}
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
	// 经租户仓储写入：版本递增与绑定同事务（原先的裸 INSERT 绕过了计数器，
	// 会让已有缓存的主体在 TTL 内看不到超管身份）。
	if err := m.repos.Assemble().UserRoles.Assign(ctx, subjectID, roleID); err != nil {
		return fmt.Errorf("rbac/modules/tenant: seed tenant super admin subject: %w", err)
	}
	// 绑定提交后再同步缓存副本（与 App.SeedSuperAdmin 一致）。
	return m.app.SyncSubjectVersion(ctx, subjectID)
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
	var row struct {
		ID        uint64
		IsBuiltin bool
	}
	err = m.db.WithContext(ctx).
		Table("rbac_roles").
		Select("id, is_builtin").
		Where("tenant_id = ? AND code = ?", tenantID, model.BuiltinSuperAdminRoleCode).
		Scan(&row).Error
	if err != nil || row.ID == 0 {
		return 0, fmt.Errorf("rbac/modules/tenant: seed tenant super admin role: readback failed: %v", err)
	}
	// 同名但非内置角色（历史脏数据）会让"种子成功"变成普通人绑定，必须拒绝。
	if !row.IsBuiltin {
		return 0, fmt.Errorf("%w: role %q in tenant %q is not builtin; refusing to seed",
			core.ErrBuiltinRoleProtected, model.BuiltinSuperAdminRoleCode, tenantID)
	}
	return row.ID, nil
}

// TenantOf 验证租户标识格式（与 core.ValidTenantID 一致）：长度 1..64、
// 字符集 [A-Za-z0-9_.-]，且不得使用保留名 "default"（平台域）与 "!global"
// （全局计数器域）。业务侧 TenantResolver 应据此校验解析结果。
func TenantOf(tenantID string) error {
	if !core.ValidTenantID(tenantID) {
		return fmt.Errorf("%w: %q", core.ErrInvalidTenantID, tenantID)
	}
	return nil
}

// 编译期确认模块迁移的 Module 键不与 Core 冲突。
var _ = migrations.CoreModule
