// Package gormrepo 集成测试：连接真实 MySQL 8.0+ 验证迁移、仓储与授权聚合。
//
// 通过环境变量门控（§9.2 使用真实数据库验证）：
//
//	RBAC_TEST_MYSQL_DSN='root:rootpass@tcp(127.0.0.1:3306)/go_rbac_test?parseTime=true&loc=UTC&charset=utf8mb4' go test ./repository/gormrepo/ -run Integration -v
//
// 未设置时整体 Skip。测试会创建并清空目标数据库中的 rbac_* 表，勿指向生产库。
package gormrepo_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/internal/repository"
	gormrepo "github.com/animacaeli/go-rbac/internal/repository/gormrepo"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/modules/audit"
	"github.com/animacaeli/go-rbac/modules/datascope"
	"github.com/animacaeli/go-rbac/modules/menu"
	"github.com/animacaeli/go-rbac/modules/template"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type IntegrationSuite struct {
	suite.Suite
	ctx     context.Context
	db      *gorm.DB
	repos   repository.Repos
	app     *rbac.App
	reg     *registry.Registry
	permIDs map[string]uint64
	audit   *audit.Module
	tpl     *template.Module
	menuM   *menu.Module
	ds      *datascope.Module
}

func TestIntegrationSuite(t *testing.T) {
	if os.Getenv("RBAC_TEST_MYSQL_DSN") == "" {
		t.Skip("RBAC_TEST_MYSQL_DSN not set; skipping MySQL integration tests")
	}
	suite.Run(t, new(IntegrationSuite))
}

func (s *IntegrationSuite) SetupSuite() {
	dsn := os.Getenv("RBAC_TEST_MYSQL_DSN")
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(s.T(), err)
	sqlDB, err := db.DB()
	require.NoError(s.T(), err)
	sqlDB.SetMaxOpenConns(4)

	s.ctx = context.Background()
	s.db = db
	s.reg = registry.NewRegistry()
	require.NoError(s.T(), s.reg.Register(
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("user:delete", "删除用户", "用户管理"),
		registry.New("order:export", "导出订单", "订单管理"),
	))

	// Phase 2：携带 audit / template 模块组装（迁移顺序 Core → 模块注册顺序）。
	s.audit = audit.New()
	s.tpl = template.New(template.Define(
		"ops_tpl", "运营模板", "模板复制演示",
		"user:list", "user:delete",
	))
	s.menuM = menu.New()
	s.ds = datascope.New()
	app, err := rbac.New(
		rbac.WithDB(db),
		rbac.WithPermissionRegistry(s.reg),
		rbac.WithModules(s.audit, s.tpl, s.menuM, s.ds),
	)
	require.NoError(s.T(), err)
	s.app = app
	s.repos = gormrepo.New(db).Assemble()

	// 每次全量重置：删表重迁移，保证测试隔离。
	s.resetSchema()
	require.NoError(s.T(), app.Migrate(s.ctx))
	_, err = app.SyncPermissions(s.ctx)
	require.NoError(s.T(), err)
	s.permIDs = s.loadPermIDs()

	require.NoError(s.T(), app.SeedSuperAdmin(s.ctx, "root-admin"))
}

func (s *IntegrationSuite) loadPermIDs() map[string]uint64 {
	perms, err := s.repos.Permissions.ListAll(s.ctx)
	require.NoError(s.T(), err)
	out := make(map[string]uint64, len(perms))
	for _, p := range perms {
		out[p.Code] = p.ID
	}
	return out
}

func (s *IntegrationSuite) resetSchema() {
	tables := []string{
		"schema_migrations",
		"rbac_audit_logs", "rbac_menu_permissions", "rbac_menus", "rbac_role_data_scopes",
		"rbac_user_grants", "rbac_role_permissions", "rbac_user_roles",
		"rbac_permissions", "rbac_roles", "rbac_counters",
	}
	for _, t := range tables {
		require.NoError(s.T(), s.db.Exec("DROP TABLE IF EXISTS "+t).Error)
	}
}

func (s *IntegrationSuite) TestMigrate_IdempotentRerun() {
	// Act：重复迁移不报错、不重复应用。
	err := s.app.Migrate(s.ctx)

	// Assert
	s.Require().NoError(err)
	var count int64
	s.Require().NoError(s.db.Table("schema_migrations").Count(&count).Error)
	// Core 0001–0004 + audit/menu/datascope 各 0001（template 无迁移）；
	// 同一版本只记录一次。
	s.Equal(int64(7), count, "重跑不产生新的版本记录")
}

func (s *IntegrationSuite) TestSyncPermissions_IdempotentRerun() {
	// Act
	result, err := s.app.SyncPermissions(s.ctx)

	// Assert：重跑无差量。
	s.Require().NoError(err)
	s.Equal(registry.SyncResult{}, result)
}

func (s *IntegrationSuite) TestRoleLifecycle() {
	ctx := s.ctx
	role, err := s.app.Roles().Create(ctx, core.AuthorizationContext{SubjectID: "root-admin"}, "ops", "运营专员", "")
	s.Require().NoError(err)

	// 元数据更新。
	s.Require().NoError(s.app.Roles().Update(ctx, core.AuthorizationContext{SubjectID: "root-admin"}, role.ID, "运营专员V2", "desc"))
	updated, err := s.repos.Roles.FindByID(ctx, role.ID)
	s.Require().NoError(err)
	s.Equal("运营专员V2", updated.Name)

	// 分配用户后再删除 → ErrRoleInUse。
	s.Require().NoError(s.repos.UserRoles.Assign(ctx, "10001", role.ID))
	err = s.app.Roles().Delete(ctx, core.AuthorizationContext{SubjectID: "root-admin"}, role.ID)
	s.ErrorIs(err, core.ErrRoleInUse)

	// 回收后可删；关联行同事务清理。
	s.Require().NoError(s.repos.UserRoles.Revoke(ctx, "10001", role.ID))
	s.Require().NoError(s.app.Roles().Delete(ctx, core.AuthorizationContext{SubjectID: "root-admin"}, role.ID))
	_, err = s.repos.Roles.FindByID(ctx, role.ID)
	s.True(repository.IsNotFound(err))
}

func (s *IntegrationSuite) TestAuthorizationFlow_RoleUnionGrantAndSuperAdmin() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}
	user := core.AuthorizationContext{SubjectID: "10001"}

	// 角色持有 user:list；另一角色持有 user:delete。
	roleA, err := s.app.Roles().Create(ctx, admin, "role_a", "A", "")
	s.Require().NoError(err)
	roleB, err := s.app.Roles().Create(ctx, admin, "role_b", "B", "")
	s.Require().NoError(err)

	// 超管分配权限与角色（豁免持权约束）。
	s.Require().NoError(s.app.Roles().SetPermissions(ctx, admin, roleA.ID, []string{"user:list"}))
	s.Require().NoError(s.app.Roles().SetPermissions(ctx, admin, roleB.ID, []string{"user:delete"}))
	s.Require().NoError(s.app.UserRoles().Assign(ctx, admin, "10001", roleA.ID))

	// 单角色：有 user:list，无 user:delete。
	ok, err := s.app.Authorizer().HasPermission(ctx, user, "user:list")
	s.Require().NoError(err)
	s.True(ok)
	ok, err = s.app.Authorizer().HasPermission(ctx, user, "user:delete")
	s.Require().NoError(err)
	s.False(ok)

	// 多角色并集。
	s.Require().NoError(s.app.UserRoles().Assign(ctx, admin, "10001", roleB.ID))
	ok, err = s.app.Authorizer().HasPermission(ctx, user, "user:delete")
	s.Require().NoError(err)
	s.True(ok)

	// 额外授权：order:export，带到期时间。
	expiry := time.Now().UTC().Add(2 * time.Hour)
	s.Require().NoError(s.app.Grants().Grant(ctx, admin, "10001", "order:export", &expiry, "临时项目"))
	ok, err = s.app.Authorizer().HasPermission(ctx, user, "order:export")
	s.Require().NoError(err)
	s.True(ok)

	// 撤销后立即失效（授权路径回源数据库）。
	s.Require().NoError(s.app.Grants().Revoke(ctx, admin, "10001", "order:export"))
	ok, err = s.app.Authorizer().HasPermission(ctx, user, "order:export")
	s.Require().NoError(err)
	s.False(ok)

	// 超管恒真 + IsSuperAdministrator。
	ok, err = s.app.Authorizer().HasPermission(ctx, admin, "anything:nope")
	s.Require().NoError(err)
	s.True(ok)
	isSuper, err := s.app.Authorizer().IsSuperAdministrator(ctx, admin)
	s.Require().NoError(err)
	s.True(isSuper)

	// 禁用角色 → 权限即时失效。
	s.Require().NoError(s.app.Roles().SetStatus(ctx, admin, roleA.ID, model.RoleStatusDisabled))
	ok, err = s.app.Authorizer().HasPermission(ctx, user, "user:list")
	s.Require().NoError(err)
	s.False(ok)
}

func (s *IntegrationSuite) TestGrantLifecycle_RegrantRevokesOldRow() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}

	s.Require().NoError(s.app.Grants().Grant(ctx, admin, "20001", "user:list", nil, "第一次"))
	// 重新授权：旧活跃行被撤销、新行插入（§2.5）。
	expiry := time.Now().UTC().Add(time.Hour)
	s.Require().NoError(s.app.Grants().Grant(ctx, admin, "20001", "user:list", &expiry, "第二次"))

	history, err := s.app.Grants().List(ctx, "20001")
	s.Require().NoError(err)
	s.Require().Len(history, 2, "撤销记录保留不删")
	// 旧记录已撤销，新记录活跃。
	var revoked, active int
	for _, g := range history {
		if g.RevokedAt != nil {
			revoked++
		} else {
			active++
		}
	}
	s.Equal(1, revoked)
	s.Equal(1, active)

	// 数据库兜底：不存在第二条未撤销行（生成列唯一约束）。
	var n int64
	s.Require().NoError(s.db.Model(&model.UserGrant{}).
		Where("subject_id = ? AND permission_id = ? AND revoked_at IS NULL", "20001", s.permIDs["user:list"]).
		Count(&n).Error)
	s.Equal(int64(1), n)
}

func (s *IntegrationSuite) TestExpiredGrant_ExcludedFromAuthorization() {
	ctx := s.ctx
	user := core.AuthorizationContext{SubjectID: "30001"}

	past := time.Now().UTC().Add(-time.Minute)
	// 直接落库一条已过期未撤销的授权（模拟时间流逝后的状态）。
	s.Require().NoError(s.repos.Grants.Grant(ctx, model.UserGrant{
		SubjectID:    "30001",
		PermissionID: s.permIDs["user:delete"],
		Reason:       "已过期",
		CreatedBy:    "root-admin",
		ExpiresAt:    &past,
	}, past.Add(-time.Hour)))

	ok, err := s.app.Authorizer().HasPermission(ctx, user, "user:delete")
	s.Require().NoError(err)
	s.False(ok, "已过期授权不得放行（§6.5 查询层校验）")
}

func (s *IntegrationSuite) TestGrantorConstraint_EnforcedAgainstRealAggregation() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}

	// 普通用户 40001 持有 user:list。
	roleC, err := s.app.Roles().Create(ctx, admin, "role_c", "C", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(ctx, admin, roleC.ID, []string{"user:list"}))
	s.Require().NoError(s.app.UserRoles().Assign(ctx, admin, "40001", roleC.ID))

	// 40001 尝试授予自己不持有的 order:export → 拒绝。
	notHolder := core.AuthorizationContext{SubjectID: "40001"}
	err = s.app.Grants().Grant(ctx, notHolder, "40002", "order:export", nil, "")
	s.ErrorIs(err, core.ErrGrantorPermissionDenied)

	// 40001 尝试分配包含未持有权限的角色 → 拒绝。
	roleD, err := s.app.Roles().Create(ctx, admin, "role_d", "D", "")
	s.Require().NoError(err)
	s.Require().NoError(s.repos.RolePermissions.SetPermissions(ctx, roleD.ID, []uint64{s.permIDs["order:export"]}))
	err = s.app.UserRoles().Assign(ctx, notHolder, "40002", roleD.ID)
	s.ErrorIs(err, core.ErrGrantorPermissionDenied)

	// 内置超管角色不可经管理接口授予。
	builtinRole, err := s.repos.Roles.FindByCode(ctx, model.BuiltinSuperAdminRoleCode)
	s.Require().NoError(err)
	err = s.app.UserRoles().Assign(ctx, admin, "40002", builtinRole.ID)
	s.ErrorIs(err, core.ErrBuiltinRoleProtected)
}

func (s *IntegrationSuite) TestValidatePermissionCodes_AgainstLiveRegistry() {
	// Arrange + Act
	err := s.app.ValidatePermissionCodes("user:list", "rbac:role:list")

	// Assert
	s.Require().NoError(err)
	err = s.app.ValidatePermissionCodes("typo:code")
	s.Require().Error(err)
	assert.Contains(s.T(), err.Error(), "typo:code")
}

func (s *IntegrationSuite) TestAuditModule_RecordsAuthorizationChanges() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}

	// Arrange + Act：角色创建 → 用户角色分配 → 额外授权 → 撤销。
	role, err := s.app.Roles().Create(ctx, admin, "audited_role", "被审计角色", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.UserRoles().Assign(ctx, admin, "50001", role.ID))
	s.Require().NoError(s.app.Grants().Grant(ctx, admin, "50001", "order:export", nil, "审计演示"))
	s.Require().NoError(s.app.Grants().Revoke(ctx, admin, "50001", "order:export"))

	// Assert：§2.10 事件全链路落库；按目标查询（套件内其它用例也会写审计，
	// 因此不能用全表计数断言）。
	q := audit.NewQuery(s.audit)
	byRole, err := q.List(ctx, audit.Filter{Subject: "audited_role"})
	s.Require().NoError(err)
	s.Require().Len(byRole, 1, "role.created 以角色 code 为目标")

	bySubject, err := q.List(ctx, audit.Filter{Subject: "50001"})
	s.Require().NoError(err)
	s.Require().Len(bySubject, 3, "assign + grant + revoke 均以被操作对象为目标")

	logs := append(byRole, bySubject...)
	types := map[string]bool{}
	for _, log := range logs {
		types[log.EventType] = true
	}
	for _, want := range []string{
		string(core.EventRoleCreated), string(core.EventUserRoleAssigned),
		string(core.EventUserGranted), string(core.EventGrantRevoked),
	} {
		s.True(types[want], "missing event %s", want)
	}
}

func (s *IntegrationSuite) TestTemplateModule_CreateFromTemplateCopiesSnapshot() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}

	// Act：从模板创建角色 = 创建 + 权限快照复制（§2.4）。
	role, err := s.tpl.CreateFromTemplate(ctx, admin, "ops_tpl", "ops_from_tpl", "运营-模板创建")
	s.Require().NoError(err)

	// Assert：权限与模板一致。
	perms, err := s.app.Roles().PermissionsOfRole(ctx, role.ID)
	s.Require().NoError(err)
	codes := make([]string, 0, len(perms))
	for _, p := range perms {
		codes = append(codes, p.Code)
	}
	s.ElementsMatch([]string{"user:list", "user:delete"}, codes)

	// 幂等重跑：角色已存在 → 对齐权限快照，不报错。
	_, err = s.tpl.CreateFromTemplate(ctx, admin, "ops_tpl", "ops_from_tpl", "运营-模板创建")
	s.Require().NoError(err)

	// 授权者约束照常生效：非持权操作者不能从含未持有权限的模板创建。
	notHolder := core.AuthorizationContext{SubjectID: "60001"}
	_, err = s.tpl.CreateFromTemplate(ctx, notHolder, "ops_tpl", "ops_hijack", "越权")
	s.ErrorIs(err, core.ErrGrantorPermissionDenied)
}

func (s *IntegrationSuite) TestPermissionService_DisableIncrementsEpoch() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}
	user := core.AuthorizationContext{SubjectID: "70001"}

	// Arrange：用户经角色持有 user:delete。
	role, err := s.app.Roles().Create(ctx, admin, "epoch_role", "E", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(ctx, admin, role.ID, []string{"user:delete"}))
	s.Require().NoError(s.app.UserRoles().Assign(ctx, admin, "70001", role.ID))
	ok, err := s.app.Authorizer().HasPermission(ctx, user, "user:delete")
	s.Require().NoError(err)
	s.True(ok)

	// Act：禁用权限（§6.3 → INCR epoch）。
	s.Require().NoError(s.app.Permissions().SetStatus(ctx, admin, "user:delete", model.PermissionStatusDisabled))

	// Assert：NoopCache 下每次回源，立即失效；重新启用后恢复。
	ok, err = s.app.Authorizer().HasPermission(ctx, user, "user:delete")
	s.Require().NoError(err)
	s.False(ok)

	s.Require().NoError(s.app.Permissions().SetStatus(ctx, admin, "user:delete", model.PermissionStatusEnabled))
	ok, err = s.app.Authorizer().HasPermission(ctx, user, "user:delete")
	s.Require().NoError(err)
	s.True(ok)
}

func (s *IntegrationSuite) TestMenuModule_DeclareAndResolveVisible() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}
	user := core.AuthorizationContext{SubjectID: "80001"}

	// Arrange：目录（无权限关联=所有人可见）+ 页面（关联 user:list）+ 外链（关联 order:export）。
	s.Require().NoError(s.menuM.Declare(ctx,
		menu.Item{Code: "biz", Name: "业务", Type: menu.TypeDirectory},
		menu.Item{Code: "biz_users", Parent: "biz", Name: "用户", Type: menu.TypePage,
			Path: "/users", Component: "UserList", Permissions: []string{"user:list"}},
		menu.Item{Code: "doc", Name: "文档", Type: menu.TypeLink, Path: "https://example.com",
			Permissions: []string{"order:export"}},
	))

	// 普通用户持有 user:list（经角色）。
	role, err := s.app.Roles().Create(ctx, admin, "menu_role", "M", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(ctx, admin, role.ID, []string{"user:list"}))
	s.Require().NoError(s.app.UserRoles().Assign(ctx, admin, "80001", role.ID))

	// Act
	tree, err := s.menuM.ResolveVisibleMenus(ctx, user)
	s.Require().NoError(err)

	// Assert：可见 = 目录（无关联）+ 用户页面（持有 user:list）；文档外链不可见。
	codes := flattenMenu(tree)
	s.ElementsMatch([]string{"biz", "biz_users"}, codes)

	// 超管可见全部（含 doc）。
	superTree, err := s.menuM.ResolveVisibleMenus(ctx, admin)
	s.Require().NoError(err)
	s.ElementsMatch([]string{"biz", "biz_users", "doc"}, flattenMenu(superTree))

	// 树形结构：biz_users 挂在 biz 下。
	s.Require().Len(tree, 1)
	s.Equal("biz", tree[0].Code)
	s.Require().Len(tree[0].Children, 1)
	s.Equal("biz_users", tree[0].Children[0].Code)
}

func flattenMenu(nodes []*menu.Node) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.Code)
		out = append(out, flattenMenu(n.Children)...)
	}
	return out
}

func (s *IntegrationSuite) TestDataScopeModule_WidestMergeAndDefaults() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}
	user := core.AuthorizationContext{SubjectID: "81001"}

	// Arrange：两个角色（都分配给用户），分别配 SELF 与 DEPARTMENT_AND_CHILDREN。
	roleA, err := s.app.Roles().Create(ctx, admin, "ds_a", "A", "")
	s.Require().NoError(err)
	roleB, err := s.app.Roles().Create(ctx, admin, "ds_b", "B", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.UserRoles().Assign(ctx, admin, "81001", roleA.ID))
	s.Require().NoError(s.app.UserRoles().Assign(ctx, admin, "81001", roleB.ID))
	s.Require().NoError(s.ds.SetRoleScope(ctx, admin, roleA.ID, "order", datascope.ScopeSelf))
	s.Require().NoError(s.ds.SetRoleScope(ctx, admin, roleB.ID, "order", datascope.ScopeDepartmentAndChildren))

	// Act + Assert：多角色取最宽（§2.8）。
	scope, err := s.ds.ResolveDataScope(ctx, user, "order")
	s.Require().NoError(err)
	s.Equal(datascope.ScopeDepartmentAndChildren, scope)

	// 未配置的资源 → 默认 SELF（deny-by-default）。
	scope, err = s.ds.ResolveDataScope(ctx, user, "invoice")
	s.Require().NoError(err)
	s.Equal(datascope.ScopeSelf, scope)

	// 超管 → ALL。
	scope, err = s.ds.ResolveDataScope(ctx, admin, "order")
	s.Require().NoError(err)
	s.Equal(datascope.ScopeAll, scope)

	// 替换式更新：调窄立即生效。
	s.Require().NoError(s.ds.SetRoleScope(ctx, admin, roleB.ID, "order", datascope.ScopeSelf))
	scope, err = s.ds.ResolveDataScope(ctx, user, "order")
	s.Require().NoError(err)
	s.Equal(datascope.ScopeSelf, scope)
}

// ---- 第八轮审核回归 ----

// 菜单可见性 fail closed：关联权限被禁用/废弃后，受控菜单不得退化为全员可见。
func (s *IntegrationSuite) TestMenuModule_DisabledPermissionFailsClosed() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}
	nobody := core.AuthorizationContext{SubjectID: "81001"}

	s.Require().NoError(s.menuM.Declare(ctx, menu.Item{
		Code: "gated", Name: "受控页面", Type: menu.TypePage, Path: "/gated",
		Permissions: []string{"order:export"},
	}))

	tree, err := s.menuM.ResolveVisibleMenus(ctx, nobody)
	s.Require().NoError(err)
	s.NotContains(flattenMenu(tree), "gated", "无权限用户不可见受控菜单")

	// 禁用关联权限（等价于 SyncPermissions 把下线权限标记为废弃）。
	s.Require().NoError(s.app.Permissions().SetStatus(ctx, admin, "order:export", model.PermissionStatusDisabled))
	s.T().Cleanup(func() {
		_ = s.app.Permissions().SetStatus(ctx, admin, "order:export", model.PermissionStatusEnabled)
	})

	tree, err = s.menuM.ResolveVisibleMenus(ctx, nobody)
	s.Require().NoError(err)
	s.NotContains(flattenMenu(tree), "gated", "关联权限全部禁用时必须 fail closed，不得退化为公开菜单")
}

// 审计查询按租户隔离：ctx 携带租户槽位时只返回该租户记录。
func (s *IntegrationSuite) TestAuditQuery_TenantScoped() {
	ctx := s.ctx
	now := time.Now().UTC()
	for _, tenant := range []string{"acme", "beta"} {
		s.Require().NoError(s.db.Create(&audit.AuditLog{
			EventType: "role.created", OperatorID: "op", TenantID: tenant,
			Target: "x", Detail: "{}", CreatedAt: now,
		}).Error)
	}
	q := audit.NewQuery(s.audit)
	logs, err := q.List(core.ContextWithTenant(ctx, "acme"), audit.Filter{})
	s.Require().NoError(err)
	s.Require().NotEmpty(logs)
	for _, l := range logs {
		s.Equal("acme", l.TenantID, "跨租户审计记录不得返回")
	}

	// 默认查询器不允许显式越界（ctx 无租户 → 任何显式租户都越界）。
	beta := "beta"
	_, err = q.List(ctx, audit.Filter{Tenant: &beta})
	s.Require().ErrorIs(err, audit.ErrTenantScopeViolation, "默认构造不得接受越界 Filter.Tenant")

	// 平台级授权端点通过 WithCrossTenantAccess 显式放开。
	crossTenant := audit.NewQuery(s.audit, audit.WithCrossTenantAccess())
	logs, err = crossTenant.List(ctx, audit.Filter{Tenant: &beta})
	s.Require().NoError(err)
	s.Require().NotEmpty(logs)
	for _, l := range logs {
		s.Equal("beta", l.TenantID)
	}
}

// 批量分配：单事务落库，且同一主体只递增一次版本号。
func (s *IntegrationSuite) TestAssignMany_SingleTransactionSingleBump() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}
	subjectID := "83001"

	r1, err := s.app.Roles().Create(ctx, admin, "batch_r1", "R1", "")
	s.Require().NoError(err)
	r2, err := s.app.Roles().Create(ctx, admin, "batch_r2", "R2", "")
	s.Require().NoError(err)

	s.Require().NoError(s.app.UserRoles().AssignBatch(ctx, admin, subjectID, []uint64{r1.ID, r2.ID}))
	roles, err := s.app.UserRoles().ListRoles(ctx, subjectID)
	s.Require().NoError(err)
	s.Len(roles, 2, "批量分配必须原子落库")

	version := func() int64 {
		var v int64
		s.Require().NoError(s.db.Table("rbac_counters").
			Select("v").Where("k = ?", "default:subject:"+subjectID+":version").Scan(&v).Error)
		return v
	}
	first := version()
	s.Equal(int64(1), first, "一次批量分配只递增一次版本")

	// 幂等重放：已存在的关联不产生新行、也不递增版本。
	s.Require().NoError(s.app.UserRoles().AssignBatch(ctx, admin, subjectID, []uint64{r1.ID, r2.ID}))
	s.Equal(first, version(), "幂等重放不得递增版本")
}

// 角色删除的"未被使用"复核在事务内完成，仍被分配时返回 ErrRoleInUse 而不是删掉绑定。
func (s *IntegrationSuite) TestRoleDelete_InUseRejectedInTransaction() {
	ctx := s.ctx
	admin := core.AuthorizationContext{SubjectID: "root-admin"}
	role, err := s.app.Roles().Create(ctx, admin, "inuse_role", "I", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.UserRoles().Assign(ctx, admin, "84001", role.ID))

	err = s.app.Roles().Delete(ctx, admin, role.ID)
	s.Require().ErrorIs(err, rbac.ErrRoleInUse)

	// 绑定仍然存在。
	roles, err := s.app.UserRoles().ListRoles(ctx, "84001")
	s.Require().NoError(err)
	s.Len(roles, 1)
}
