// Package datascope 实现数据权限模块（§2.8）：与功能权限分离的枚举型数据范围。
//
// 四种范围（§2.8 冻结决策）与合并语义：
//
//	ScopeSelf < ScopeDepartment < ScopeDepartmentAndChildren < ScopeAll
//
// 多角色数据范围合并 = 取最宽（对枚举型范围，并集语义数学上等价于取最宽）；
// CUSTOM（自定义范围）延后至独立设计（docs/phase3-evaluation.md）。
//
// 模块只提供范围解析；业务项目负责将结果应用到具体查询，并负责组织关系
// 与业务字段映射（§2.8）。示例：
//
//	scope, err := ds.ResolveDataScope(ctx, ac, "order")
//	switch scope {
//	case datascope.ScopeAll: // 不加过滤
//	case datascope.ScopeSelf: query.Where("owner_id = ?", subjectID)
//	...
//	}
//
// 默认值：角色未配置数据范围时取最窄的 ScopeSelf（deny-by-default，§7.1）。
// 超级管理员恒为 ScopeAll。
//
// 注意：本模块不产生功能权限缓存的影响（数据范围不走权限缓存）；
// 启用多租户后，主体角色按其租户解析（§2.9），见 tenant 模块。
package datascope

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/model"
	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var scopeFS embed.FS

// Scope 是枚举型数据范围；数值大小即宽度序（§2.8）。
type Scope uint8

const (
	// ScopeSelf 仅本人数据。
	ScopeSelf Scope = 1
	// ScopeDepartment 本部门数据。
	ScopeDepartment Scope = 2
	// ScopeDepartmentAndChildren 本部门及下级部门数据。
	ScopeDepartmentAndChildren Scope = 3
	// ScopeAll 全部数据。
	ScopeAll Scope = 4
)

// String 返回可读名称。
func (s Scope) String() string {
	switch s {
	case ScopeSelf:
		return "SELF"
	case ScopeDepartment:
		return "DEPARTMENT"
	case ScopeDepartmentAndChildren:
		return "DEPARTMENT_AND_CHILDREN"
	case ScopeAll:
		return "ALL"
	default:
		return fmt.Sprintf("INVALID(%d)", uint8(s))
	}
}

// Valid 报告是否为合法枚举值。
func (s Scope) Valid() bool {
	return s >= ScopeSelf && s <= ScopeAll
}

// Wider 返回两者中更宽的范围（多角色合并语义，§2.8）。
func Wider(a, b Scope) Scope {
	if a >= b {
		return a
	}
	return b
}

// roleDataScope 对应表 rbac_role_data_scopes。
type roleDataScope struct {
	ID        uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	RoleID    uint64    `gorm:"column:role_id;not null;uniqueIndex:uk_role_resource,priority:1"`
	Resource  string    `gorm:"column:resource;size:64;not null;uniqueIndex:uk_role_resource,priority:2"`
	Scope     Scope     `gorm:"column:scope;not null"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime:milli"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:milli"`
}

func (roleDataScope) TableName() string { return "rbac_role_data_scopes" }

// Module 是数据范围模块（实现 rbac.Module）。
// 服务经 app 惰性获取：tenant 等模块可能在 Register 期替换仓储与服务。
type Module struct {
	app *rbac.App
}

var _ rbac.Module = (*Module)(nil)

// New 构造数据范围模块。
func New() *Module { return &Module{} }

// Name 返回模块名。
func (m *Module) Name() string { return "datascope" }

// Dependencies 声明依赖的模块名（当前无模块间依赖）。
func (m *Module) Dependencies() []string { return nil }

// Register 捕获 App 引用（不触库，§3.3）。
func (m *Module) Register(app *rbac.App) error {
	m.app = app
	return nil
}

func (m *Module) db() *gorm.DB           { return m.app.DB() }
func (m *Module) authz() core.Authorizer { return m.app.Authorizer() }

// Migrations 返回模块迁移（§5.6）。
func (m *Module) Migrations() []rbac.Migration {
	data, err := scopeFS.ReadFile("migrations/0001_data_scopes.sql")
	if err != nil {
		panic(fmt.Sprintf("rbac/modules/datascope: read embedded migration: %v", err))
	}
	return []rbac.Migration{
		{Module: m.Name(), Version: "0001", Name: "data_scopes", SQL: string(data)},
	}
}

// SetRoleScope 设置（替换式）某角色在某资源上的数据范围。幂等。
// 内置超管角色的数据范围无意义（解析恒为 ScopeAll），设置将被拒绝以免误导。
//
// 多租户：角色必须属于 operator 的授权域，否则返回 NotFound——角色 ID 全局
// 唯一，缺此校验时 A 租户可按 ID 改写 B 租户角色的数据范围（§2.9）。
func (m *Module) SetRoleScope(ctx context.Context, operator core.AuthorizationContext, roleID uint64, resource string, scope Scope) error {
	if m.app == nil {
		return fmt.Errorf("rbac/modules/datascope: module not registered")
	}
	if !scope.Valid() {
		return fmt.Errorf("rbac/modules/datascope: invalid scope %d", uint8(scope))
	}
	if resource == "" || len(resource) > model.RoleCodeMaxLength {
		return fmt.Errorf("rbac/modules/datascope: invalid resource %q", resource)
	}
	if m.app.TenancyEnabled() {
		if operator.TenantID == "" {
			return core.ErrTenantRequired
		}
		if !core.ValidTenantID(operator.TenantID) {
			return fmt.Errorf("%w: %q", core.ErrInvalidTenantID, operator.TenantID)
		}
	}
	ctx = core.ContextWithTenant(ctx, operator.TenantID)

	var role struct {
		ID        uint64
		IsBuiltin bool
	}
	roleQuery := m.db().WithContext(ctx).
		Table("rbac_roles").
		Select("id, is_builtin").
		Where("id = ?", roleID)
	if m.app.TenancyEnabled() {
		roleQuery = roleQuery.Where("tenant_id = ?", operator.TenantID)
	}
	if err := roleQuery.Scan(&role).Error; err != nil {
		return err
	}
	if role.ID == 0 {
		return fmt.Errorf("%w: role id=%d", repository.ErrRecordNotFound, roleID)
	}
	if role.IsBuiltin {
		return fmt.Errorf("%w: builtin role data scope is meaningless (always ALL)", core.ErrBuiltinRoleProtected)
	}

	// Upsert：先查后写，唯一键 (role_id, resource) 兜底并发。
	var existing roleDataScope
	err := m.db().WithContext(ctx).
		Where("role_id = ? AND resource = ?", roleID, resource).
		First(&existing).Error
	switch {
	case err == nil:
		return m.db().WithContext(ctx).
			Model(&roleDataScope{}).
			Where("id = ?", existing.ID).
			Update("scope", scope).Error
	case repository.IsNotFound(err), errors.Is(err, gorm.ErrRecordNotFound):
		row := roleDataScope{RoleID: roleID, Resource: resource, Scope: scope}
		return m.db().WithContext(ctx).Create(&row).Error
	default:
		return err
	}
}

// RemoveRoleScope 清除角色的资源数据范围（回落到默认 ScopeSelf）。
// 多租户下先校验角色属于 ctx（由调用方经 core.ContextWithTenant 注入）的授权域。
func (m *Module) RemoveRoleScope(ctx context.Context, roleID uint64, resource string) error {
	if m.app == nil {
		return fmt.Errorf("rbac/modules/datascope: module not registered")
	}
	if err := m.requireRoleInScope(ctx, roleID); err != nil {
		return err
	}
	return m.db().WithContext(ctx).
		Where("role_id = ? AND resource = ?", roleID, resource).
		Delete(&roleDataScope{}).Error
}

// requireRoleInScope 校验角色存在且（启用多租户时）属于 ctx 的授权域。
func (m *Module) requireRoleInScope(ctx context.Context, roleID uint64) error {
	q := m.db().WithContext(ctx).Table("rbac_roles").Where("id = ?", roleID)
	if m.app.TenancyEnabled() {
		tenant, ok := core.TenantFromContext(ctx)
		if !ok {
			return fmt.Errorf("rbac/modules/datascope: tenant scope missing in context (fail closed)")
		}
		q = q.Where("tenant_id = ?", tenant)
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: role id=%d", repository.ErrRecordNotFound, roleID)
	}
	return nil
}

// RoleScopes 返回角色在各资源上的数据范围（管理界面展示用）。
// 多租户下先校验角色属于 ctx 的授权域。
func (m *Module) RoleScopes(ctx context.Context, roleID uint64) (map[string]Scope, error) {
	if m.app == nil {
		return nil, fmt.Errorf("rbac/modules/datascope: module not registered")
	}
	if err := m.requireRoleInScope(ctx, roleID); err != nil {
		return nil, err
	}
	var rows []roleDataScope
	if err := m.db().WithContext(ctx).
		Where("role_id = ?", roleID).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]Scope, len(rows))
	for _, r := range rows {
		out[r.Resource] = r.Scope
	}
	return out, nil
}

// ResolveDataScope 解析主体在某资源上的数据范围（§2.8）：
//
//   - 超级管理员 → ScopeAll
//   - 多角色合并 → 取最宽（§2.8 冻结决策）
//   - 无任何角色配置了该资源 → ScopeSelf（deny-by-default）
func (m *Module) ResolveDataScope(ctx context.Context, ac core.AuthorizationContext, resource string) (Scope, error) {
	if m.app == nil {
		return 0, fmt.Errorf("rbac/modules/datascope: module not registered")
	}
	// 仅校验主体标识；租户合法性由租户策略（authorizer.validateAC）管辖，
	// 本模块按 ac 的授权域解析并注入 ctx。
	if ac.SubjectID.IsEmpty() || len(ac.SubjectID) > model.SubjectIDMaxLength {
		return 0, core.ErrInvalidSubjectID
	}
	ctx = core.ContextWithTenant(ctx, ac.TenantID)

	isSuper, err := m.authz().IsSuperAdministrator(ctx, ac)
	if err != nil {
		return 0, err
	}
	if isSuper {
		return ScopeAll, nil
	}

	// 主体全部启用角色中，该资源上配置的最宽范围。
	// 多租户：同一 subject_id 可存在于多个租户，必须按授权域过滤 ur/r，
	// 否则 A 租户配置的宽范围会泄漏给 B 租户的同名主体（§2.9）。
	var widest *Scope
	var rows []roleDataScope
	scopeQuery := m.db().WithContext(ctx).
		Table("rbac_role_data_scopes AS rds").
		Joins("JOIN rbac_user_roles ur ON ur.role_id = rds.role_id").
		Joins("JOIN rbac_roles r ON r.id = ur.role_id AND r.status = ?", model.RoleStatusEnabled).
		Where("ur.subject_id = ? AND rds.resource = ?", ac.SubjectID.String(), resource)
	if m.app.TenancyEnabled() {
		scopeQuery = scopeQuery.Where("ur.tenant_id = ? AND r.tenant_id = ?", ac.TenantID, ac.TenantID)
	}
	if err := scopeQuery.Select("rds.scope").Scan(&rows).Error; err != nil {
		return 0, err
	}
	for _, r := range rows {
		if !r.Scope.Valid() {
			continue
		}
		if widest == nil {
			w := r.Scope
			widest = &w
		} else {
			w := Wider(*widest, r.Scope)
			widest = &w
		}
	}
	if widest == nil {
		return ScopeSelf, nil
	}
	return *widest, nil
}
