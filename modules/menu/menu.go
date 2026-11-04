// Package menu 实现菜单模块（§2.7）：菜单是前端导航资源，不等同于权限资源。
//
// 与权限的可选关联（OR 语义）：
//   - 菜单可不关联权限 → 对所有已认证用户可见
//   - 菜单可关联多个权限 → 持有任一关联权限（启用状态）即可见
//
// 边界（§2.7 冻结决策）：前端隐藏菜单只是用户体验优化，后端必须独立完成鉴权。
//
// 用法：
//
//	m := menu.New()
//	app, _ := rbac.New(rbac.WithDB(db), rbac.WithPermissionRegistry(reg), rbac.WithModules(m))
//	// 声明菜单（幂等 upsert 元数据 + 权限关联）
//	_ = m.Declare(ctx, menu.Item{Code: "user_mgr", Name: "用户管理", Type: menu.TypeDirectory},
//	    menu.Item{Code: "user_list", Parent: "user_mgr", Name: "用户列表", Type: menu.TypePage,
//	        Path: "/users", Component: "UserList", Permissions: []string{"user:list"}})
//	// 解析某主体可见的菜单树
//	tree, err := m.ResolveVisibleMenus(ctx, ac)
package menu

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

//go:embed migrations/*.sql
var menuFS embed.FS

// 菜单类型（§2.7）。
const (
	TypeDirectory uint8 = 1 // 目录
	TypePage      uint8 = 2 // 页面
	TypeLink      uint8 = 3 // 外部链接
)

// Menu 对应表 rbac_menus。
type Menu struct {
	ID        uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	ParentID  uint64    `gorm:"column:parent_id;not null;default:0"`
	Code      string    `gorm:"column:code;size:64;uniqueIndex:uk_code;not null"`
	Name      string    `gorm:"column:name;size:128;not null"`
	Type      uint8     `gorm:"column:type;not null"`
	Path      string    `gorm:"column:path;size:255;not null;default:''"`
	Component string    `gorm:"column:component;size:255;not null;default:''"`
	Icon      string    `gorm:"column:icon;size:64;not null;default:''"`
	Sort      int       `gorm:"column:sort;not null;default:0"`
	Status    uint8     `gorm:"column:status;not null;default:1"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime:milli"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:milli"`
}

// TableName 返回表名。
func (Menu) TableName() string { return "rbac_menus" }

// MenuPermission 对应表 rbac_menu_permissions。
type MenuPermission struct {
	ID           uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	MenuID       uint64    `gorm:"column:menu_id;not null;uniqueIndex:uk_menu_permission,priority:1"`
	PermissionID uint64    `gorm:"column:permission_id;not null;uniqueIndex:uk_menu_permission,priority:2;index:idx_permission"`
	CreatedAt    time.Time `gorm:"column:created_at;autoCreateTime:milli"`
}

// TableName 返回表名。
func (MenuPermission) TableName() string { return "rbac_menu_permissions" }

// Item 是一条菜单声明（Declare 的输入），以 Code 为稳定标识。
type Item struct {
	Code        string
	Parent      string // 父菜单 Code，空 = 根
	Name        string
	Type        uint8 // TypeDirectory / TypePage / TypeLink
	Path        string
	Component   string
	Icon        string
	Sort        int
	Permissions []string // 关联权限码（替换式）
}

// Node 是可见菜单树节点。
type Node struct {
	Menu
	Children []*Node `json:"children,omitempty"`
}

// Module 是菜单模块（实现 rbac.Module）。
// 服务经 app 惰性获取：tenant 等模块可能在 Register 期替换仓储与服务。
type Module struct {
	app *rbac.App
}

var _ rbac.Module = (*Module)(nil)

// New 构造菜单模块。
func New() *Module { return &Module{} }

// Name 返回模块名。
func (m *Module) Name() string { return "menu" }

// Dependencies 声明依赖的模块名（当前无模块间依赖）。
func (m *Module) Dependencies() []string { return nil }

// Register 捕获 App 引用（只做注册，不触库，§3.3）。
func (m *Module) Register(app *rbac.App) error {
	m.app = app
	return nil
}

func (m *Module) db() *gorm.DB                     { return m.app.DB() }
func (m *Module) authz() core.Authorizer           { return m.app.Authorizer() }
func (m *Module) reg() *registry.Registry          { return m.app.Registry() }
func (m *Module) perms() repository.PermissionRepo { return m.app.PermissionsRepository() }

// Migrations 返回模块迁移（§5.6）。
func (m *Module) Migrations() []rbac.Migration {
	data, err := menuFS.ReadFile("migrations/0001_menus.sql")
	if err != nil {
		panic(fmt.Sprintf("rbac/modules/menu: read embedded migration: %v", err))
	}
	return []rbac.Migration{
		{Module: m.Name(), Version: "0001", Name: "menus", SQL: string(data)},
	}
}

// Declare 以声明方式幂等 upsert 菜单：按 Code 定位，新增或更新元数据与权限关联。
// 声明式接入与 Registry 的哲学一致：菜单结构由代码定义，数据库只是存储。
func (m *Module) Declare(ctx context.Context, items ...Item) error {
	if m.app == nil {
		return fmt.Errorf("rbac/modules/menu: module not registered")
	}
	// 先全部落菜单行（父先于子处理依赖）。
	byCode := make(map[string]uint64, len(items))
	for _, it := range items {
		if err := validateCode(it.Code); err != nil {
			return err
		}
		if it.Parent != "" {
			if _, ok := byCode[it.Parent]; !ok {
				// 父可能是已存在的菜单，也可能是本轮稍后声明——先查库。
				var parentID uint64
				err := m.db().WithContext(ctx).
					Table("rbac_menus").Where("code = ?", it.Parent).
					Select("id").Scan(&parentID).Error
				if err != nil {
					return err
				}
				if parentID == 0 {
					return fmt.Errorf("rbac/modules/menu: parent %s not found for %s (declare parents first)", it.Parent, it.Code)
				}
				byCode[it.Parent] = parentID
			}
		}
		menu, err := m.upsert(ctx, it, byCode[it.Parent])
		if err != nil {
			return err
		}
		byCode[it.Code] = menu.ID
	}
	// 再处理权限关联（依赖菜单行已存在）。
	for _, it := range items {
		if err := m.setPermissions(ctx, byCode[it.Code], it.Permissions); err != nil {
			return err
		}
	}
	return nil
}

func validateCode(code string) error {
	if code == "" || len(code) > model.RoleCodeMaxLength {
		return fmt.Errorf("rbac/modules/menu: invalid menu code %q", code)
	}
	return nil
}

func (m *Module) upsert(ctx context.Context, it Item, parentID uint64) (*Menu, error) {
	if strings.TrimSpace(it.Name) == "" || len(it.Name) > model.NameMaxLength {
		return nil, fmt.Errorf("rbac/modules/menu: menu %s requires name (1-%d chars)", it.Code, model.NameMaxLength)
	}
	if it.Type != TypeDirectory && it.Type != TypePage && it.Type != TypeLink {
		return nil, fmt.Errorf("rbac/modules/menu: menu %s invalid type %d", it.Code, it.Type)
	}
	var existing Menu
	err := m.db().WithContext(ctx).Where("code = ?", it.Code).First(&existing).Error
	switch err {
	case nil:
		existing.ParentID = parentID
		existing.Name = it.Name
		existing.Type = it.Type
		existing.Path = it.Path
		existing.Component = it.Component
		existing.Icon = it.Icon
		existing.Sort = it.Sort
		if err := m.db().WithContext(ctx).Save(&existing).Error; err != nil {
			return nil, err
		}
		return &existing, nil
	default:
		if !repository.IsNotFound(err) && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		created := Menu{
			ParentID: parentID, Code: it.Code, Name: it.Name, Type: it.Type,
			Path: it.Path, Component: it.Component, Icon: it.Icon, Sort: it.Sort,
			Status: model.RoleStatusEnabled,
		}
		if err := m.db().WithContext(ctx).Create(&created).Error; err != nil {
			return nil, err
		}
		return &created, nil
	}
}

// setPermissions 替换式设置菜单权限关联；空清单 = 清除关联（菜单对所有人可见）。
func (m *Module) setPermissions(ctx context.Context, menuID uint64, codes []string) error {
	if len(codes) == 0 {
		return m.db().WithContext(ctx).
			Where("menu_id = ?", menuID).
			Delete(&MenuPermission{}).Error
	}
	distinct := make([]string, 0, len(codes))
	seen := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		if _, dup := seen[c]; dup {
			continue
		}
		if !m.reg().Has(c) {
			return fmt.Errorf("rbac/modules/menu: menu permission %s is not registered", c)
		}
		seen[c] = struct{}{}
		distinct = append(distinct, c)
	}
	perms, err := m.perms().FindByCodes(ctx, distinct)
	if err != nil {
		return err
	}
	if len(perms) != len(distinct) {
		return fmt.Errorf("rbac/modules/menu: some permissions missing from database (run SyncPermissions first)")
	}

	return m.db().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("menu_id = ?", menuID).Delete(&MenuPermission{}).Error; err != nil {
			return err
		}
		rows := make([]MenuPermission, 0, len(perms))
		for _, p := range perms {
			rows = append(rows, MenuPermission{MenuID: menuID, PermissionID: p.ID})
		}
		return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
	})
}

// SetStatus 启用/禁用菜单。
func (m *Module) SetStatus(ctx context.Context, code string, status uint8) error {
	if status != model.RoleStatusEnabled && status != model.RoleStatusDisabled {
		return fmt.Errorf("rbac/modules/menu: invalid status %d", status)
	}
	res := m.db().WithContext(ctx).Model(&Menu{}).Where("code = ?", code).Update("status", status)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: menu %s", repository.ErrRecordNotFound, code)
	}
	return nil
}

// ResolveVisibleMenus 返回主体可见的启用菜单树（§2.7 OR 语义）：
// 超级管理员可见全部；其余主体：无权限关联的菜单可见，有关联的需持有
// 任一关联权限。禁用菜单及其子树不返回。
func (m *Module) ResolveVisibleMenus(ctx context.Context, ac core.AuthorizationContext) ([]*Node, error) {
	if m.app == nil {
		return nil, fmt.Errorf("rbac/modules/menu: module not registered")
	}
	var menus []Menu
	if err := m.db().WithContext(ctx).
		Where("status = ?", model.RoleStatusEnabled).
		Order("sort ASC, id ASC").
		Find(&menus).Error; err != nil {
		return nil, err
	}
	if len(menus) == 0 {
		return nil, nil
	}

	isSuper, err := m.authz().IsSuperAdministrator(ctx, ac)
	if err != nil {
		return nil, err
	}

	// 菜单 → 关联的启用权限码。
	type mpRow struct {
		MenuID uint64
		Code   string
	}
	var rows []mpRow
	if err := m.db().WithContext(ctx).
		Table("rbac_menu_permissions AS mp").
		Joins("JOIN rbac_permissions p ON p.id = mp.permission_id AND p.status = ?", model.PermissionStatusEnabled).
		Select("mp.menu_id AS menu_id, p.code AS code").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	menuPerms := make(map[uint64][]string, len(rows))
	for _, r := range rows {
		menuPerms[r.MenuID] = append(menuPerms[r.MenuID], r.Code)
	}

	held := map[string]struct{}{}
	if !isSuper {
		perms, err := m.authz().GetPermissions(ctx, ac)
		if err != nil {
			return nil, err
		}
		for _, p := range perms {
			held[p] = struct{}{}
		}
	}

	visible := make(map[uint64]*Node, len(menus))
	for i := range menus {
		mu := menus[i]
		if !isSuper {
			required, ok := menuPerms[mu.ID]
			if ok && len(required) > 0 {
				any := false
				for _, code := range required {
					if _, has := held[code]; has {
						any = true
						break
					}
				}
				if !any {
					continue
				}
			}
		}
		visible[mu.ID] = &Node{Menu: mu}
	}

	return buildTree(visible), nil
}

// buildTree 由可见节点装配森林；父不可见时子节点提升为根（导航不因中间层
// 缺失而丢失叶子）。
func buildTree(visible map[uint64]*Node) []*Node {
	var roots []*Node
	for _, node := range visible {
		if parent, ok := visible[node.ParentID]; ok {
			parent.Children = append(parent.Children, node)
		} else {
			roots = append(roots, node)
		}
	}
	var sortNodes func(nodes []*Node)
	sortNodes = func(nodes []*Node) {
		sort.Slice(nodes, func(i, j int) bool {
			if nodes[i].Sort != nodes[j].Sort {
				return nodes[i].Sort < nodes[j].Sort
			}
			return nodes[i].ID < nodes[j].ID
		})
		for _, n := range nodes {
			if len(n.Children) > 0 {
				sortNodes(n.Children)
			}
		}
	}
	sortNodes(roots)
	return roots
}
