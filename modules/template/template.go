// Package template 实现角色模板模块（§2.4）：开发人员预设常用角色配置，
// 创建角色时复制模板权限（Snapshot / Copy 模式）。
//
// 语义边界（§2.4 冻结决策）：
//   - 模板在代码中声明，CreateFromTemplate 复制当前模板权限快照
//   - 后续模板变化不自动影响已创建角色（初期不实现自动同步）
//   - 授权者持权约束照常生效（模板只是权限集合的预设，不绕过 §2.2）
//
// 用法：
//
//	tpl := template.New(
//	    template.Define("ops_lead", "运营主管", "用户与订单管理",
//	        "user:list", "order:list", "order:export"),
//	)
//	app, _ := rbac.New(rbac.WithDB(db), rbac.WithModules(tpl))
//	role, err := tpl.CreateFromTemplate(ctx, operator, "ops_lead", "ops_42", "运营主管-42")
package template

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/model"
)

// Module 是角色模板模块（实现 rbac.Module）。
// 服务经 app 惰性获取：tenant 等模块可能在 Register 期替换仓储与服务。
type Module struct {
	templates map[string]Definition
	app       *rbac.App
}

var _ rbac.Module = (*Module)(nil)

// Definition 是一条角色模板声明。
type Definition struct {
	Code            string
	Name            string
	Description     string
	PermissionCodes []string
}

// Define 构造模板定义。
func Define(code, name, description string, permissionCodes ...string) Definition {
	return Definition{Code: code, Name: name, Description: description, PermissionCodes: permissionCodes}
}

// New 构造模板模块。
func New(defs ...Definition) *Module {
	m := &Module{templates: make(map[string]Definition, len(defs))}
	for _, d := range defs {
		m.templates[d.Code] = d
	}
	return m
}

// Name 返回模块名。
func (m *Module) Name() string { return "template" }

// Register 校验模板引用的权限码均已在 Registry 注册（fail fast，§3.3），
// 并捕获 Core 角色服务。不做数据库操作。
func (m *Module) Register(app *rbac.App) error {
	m.app = app
	reg := app.Registry()
	for code, def := range m.templates {
		if strings.TrimSpace(def.Name) == "" {
			return fmt.Errorf("rbac/modules/template: template %s missing name", code)
		}
		for _, perm := range def.PermissionCodes {
			if !reg.Has(perm) {
				return fmt.Errorf("rbac/modules/template: template %s references unregistered permission %s", code, perm)
			}
		}
	}
	return nil
}

// Migrations 模板 v1 为代码声明形态，无数据库迁移（§5.6 表结构推迟至
// 模板需要经管理接口维护时引入）。
func (m *Module) Migrations() []rbac.Migration { return nil }

// CreateFromTemplate 按模板创建角色并复制模板权限（Snapshot / Copy，§2.4）。
// 复制发生在创建时刻：后续模板变化不影响该角色。
// 授权者持权约束照常生效：operator 必须持有模板全部权限（超管除外）。
func (m *Module) CreateFromTemplate(ctx context.Context, operator core.AuthorizationContext, templateCode, roleCode, roleName string) (*model.Role, error) {
	tpl, ok := m.templates[templateCode]
	if !ok {
		return nil, fmt.Errorf("rbac/modules/template: unknown template %s", templateCode)
	}
	// 幂等：角色已存在时仅刷新权限快照（便于按模板重建/对齐）。
	role, err := m.app.Roles().Create(ctx, operator, roleCode, roleName, tpl.Description)
	if err != nil {
		if !isRoleCodeExists(err) {
			return nil, err
		}
		role, err = m.app.Roles().FindByCode(ctx, roleCode)
		if err != nil {
			return nil, err
		}
	}
	codes := sortedCopy(tpl.PermissionCodes)
	if err := m.app.Roles().SetPermissions(ctx, operator, role.ID, codes); err != nil {
		return nil, err
	}
	return role, nil
}

// Templates 返回全部模板定义（按 code 排序）。
func (m *Module) Templates() []Definition {
	out := make([]Definition, 0, len(m.templates))
	for _, def := range m.templates {
		out = append(out, def)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

func isRoleCodeExists(err error) bool {
	return errors.Is(err, core.ErrRoleCodeExists)
}

func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}
