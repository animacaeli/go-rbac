// Package tenant 集成测试：迁移契约（§5.5，模块第一验收项）与双租户隔离。
//
// 环境变量门控：RBAC_TEST_MYSQL_DSN（使用独立数据库 go_rbac_tenant_test，
// 与其他集成套件并行互不干扰）。
package tenant_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/animacaeli/go-rbac"
	rediscache "github.com/animacaeli/go-rbac/cache/redis"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/modules/tenant"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// MigrationContractSuite 验证 §5.5 迁移契约：升级路径（先 Core 存量数据、
// 后 tenant 迁移）与全新路径（Core + tenant 一次迁移）。
type MigrationContractSuite struct {
	suite.Suite
	ctx context.Context
	db  *gorm.DB
}

func TestMigrationContractSuite(t *testing.T) {
	if os.Getenv("RBAC_TEST_MYSQL_DSN") == "" {
		t.Skip("RBAC_TEST_MYSQL_DSN not set; skipping tenant migration contract tests")
	}
	suite.Run(t, new(MigrationContractSuite))
}

func (s *MigrationContractSuite) SetupSuite() {
	s.ctx = context.Background()
	db := s.openDB("go_rbac_tenant_test")
	for _, t := range []string{
		"schema_migrations", "rbac_user_grants", "rbac_role_permissions",
		"rbac_user_roles", "rbac_permissions", "rbac_roles",
	} {
		require.NoError(s.T(), db.Exec("DROP TABLE IF EXISTS "+t).Error)
	}
	s.db = db
}

func (s *MigrationContractSuite) openDB(name string) *gorm.DB {
	dsn := os.Getenv("RBAC_TEST_MYSQL_DSN")
	admin, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(s.T(), err)
	require.NoError(s.T(), admin.Exec("CREATE DATABASE IF NOT EXISTS "+name+" CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci").Error)
	db, err := gorm.Open(mysql.Open(swapDB(dsn, name)), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(s.T(), err)
	return db
}

func swapDB(dsn, newDB string) string {
	q := ""
	if i := strings.Index(dsn, "?"); i >= 0 {
		dsn, q = dsn[:i], dsn[i:]
	}
	if i := strings.LastIndex(dsn, "/"); i >= 0 {
		return dsn[:i+1] + newDB + q
	}
	return dsn
}

func (s *MigrationContractSuite) newApp(withTenant bool) *rbac.App {
	reg := registry.NewRegistry()
	require.NoError(s.T(), reg.Register(registry.New("user:list", "用户列表", "用户管理")))
	opts := []rbac.Option{rbac.WithDB(s.db), rbac.WithPermissionRegistry(reg)}
	if withTenant {
		opts = append(opts, rbac.WithModules(tenant.New()))
	}
	app, err := rbac.New(opts...)
	require.NoError(s.T(), err)
	return app
}

// 契约第 1 步：仅 Core 迁移 + 存量数据。
func (s *MigrationContractSuite) seedLegacyData() {
	app := s.newApp(false)
	require.NoError(s.T(), app.Migrate(s.ctx))
	_, err := app.SyncPermissions(s.ctx)
	require.NoError(s.T(), err)
	require.NoError(s.T(), app.SeedSuperAdmin(s.ctx, "legacy-admin"))
	admin := core.AuthorizationContext{SubjectID: "legacy-admin"}
	role, err := app.Roles().Create(s.ctx, admin, "ops", "运营", "")
	require.NoError(s.T(), err)
	require.NoError(s.T(), app.Roles().SetPermissions(s.ctx, admin, role.ID, []string{"user:list"}))
	require.NoError(s.T(), app.UserRoles().Assign(s.ctx, admin, "10001", role.ID))
}

func (s *MigrationContractSuite) TestContract_UpgradePath_ColumnsBackfilledAndKeysRebuilt() {
	// Arrange：先落存量数据（Core-only）。
	s.seedLegacyData()

	// Act：应用 tenant 迁移（§5.5：加列 → 回填 → 重建三唯一键）。
	app := s.newApp(true)
	require.NoError(s.T(), app.Migrate(s.ctx))

	// Assert：列存在。
	for _, table := range []string{"rbac_roles", "rbac_user_roles", "rbac_user_grants"} {
		var n int64
		require.NoError(s.T(), s.db.Raw(
			"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = 'tenant_id'",
			table,
		).Scan(&n).Error, table)
		s.Equal(int64(1), n, "%s 必须有 tenant_id 列", table)
	}

	// Assert：存量数据回填到 default 域（tenant_id=''）。
	for _, table := range []string{"rbac_roles", "rbac_user_roles", "rbac_user_grants"} {
		var n int64
		require.NoError(s.T(), s.db.Raw(
			"SELECT COUNT(*) FROM "+table+" WHERE tenant_id != ''",
		).Scan(&n).Error)
		s.Equal(int64(0), n, "%s 存量行必须落在 default 域", table)
	}
	var roles int64
	require.NoError(s.T(), s.db.Raw("SELECT COUNT(*) FROM rbac_roles WHERE code IN ('ops', 'super_admin')").Scan(&roles).Error)
	s.Equal(int64(2), roles, "存量角色完整保留")

	// Assert：唯一键重建——同 code 跨租户可行、同租户内仍唯一。
	require.NoError(s.T(), s.db.Exec(
		"INSERT INTO rbac_roles (tenant_id, code, name, status, created_at, updated_at) VALUES ('acme', 'ops', '跨租户同名', 1, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))",
	).Error, "同 code 不同租户必须可行（uk_tenant_code）")
	err := s.db.Exec(
		"INSERT INTO rbac_roles (tenant_id, code, name, status, created_at, updated_at) VALUES ('', 'ops', '重复', 1, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))",
	).Error
	require.Error(s.T(), err, "同租户内同 code 仍必须被唯一键拒绝")

	// user_grants 唯一键按租户重建。
	require.NoError(s.T(), s.db.Exec(
		"INSERT INTO rbac_user_grants (tenant_id, subject_id, permission_id, reason, created_by, created_at) VALUES ('acme', '10001', 1, 'x', 'a', UTC_TIMESTAMP(3))",
	).Error)
	require.NoError(s.T(), s.db.Exec(
		"INSERT INTO rbac_user_grants (tenant_id, subject_id, permission_id, reason, created_by, created_at) VALUES ('beta', '10001', 1, 'x', 'a', UTC_TIMESTAMP(3))",
	).Error, "同 (subject, permission) 不同租户必须可行")
	err = s.db.Exec(
		"INSERT INTO rbac_user_grants (tenant_id, subject_id, permission_id, reason, created_by, created_at) VALUES ('acme', '10001', 1, 'y', 'a', UTC_TIMESTAMP(3))",
	).Error
	require.Error(s.T(), err, "同租户内同 (subject, permission) 活跃授权仍必须被拒绝")
}

func (s *MigrationContractSuite) TestContract_FreshPath_CoreThenTenantInOnePlan() {
	// Arrange：全新库直接带 tenant 模块安装。
	app := s.newApp(true)

	// Act
	require.NoError(s.T(), app.Migrate(s.ctx))
	require.NoError(s.T(), app.Migrate(s.ctx), "幂等重跑")

	// Assert：Core 迁移在前、tenant 在后（Plan 顺序）。
	var versions []string
	require.NoError(s.T(), s.db.Raw(
		"SELECT version FROM schema_migrations ORDER BY module, version",
	).Scan(&versions).Error)
	s.Equal([]string{"0001", "0001"}, versions)
}

// IsolationSuite 双租户隔离验证（§2.9 承担项）。
type IsolationSuite struct {
	suite.Suite
	ctx     context.Context
	db      *gorm.DB
	mr      *miniredis.Miniredis
	app     *rbac.App
	tenantM *tenant.Module
}

func TestIsolationSuite(t *testing.T) {
	if os.Getenv("RBAC_TEST_MYSQL_DSN") == "" {
		t.Skip("RBAC_TEST_MYSQL_DSN not set; skipping tenant isolation tests")
	}
	suite.Run(t, new(IsolationSuite))
}

func (s *IsolationSuite) SetupSuite() {
	s.ctx = context.Background()
	db := s.openDB("go_rbac_tenant_iso")
	for _, t := range []string{
		"schema_migrations", "rbac_user_grants", "rbac_role_permissions",
		"rbac_user_roles", "rbac_permissions", "rbac_roles",
	} {
		require.NoError(s.T(), db.Exec("DROP TABLE IF EXISTS "+t).Error)
	}
	s.db = db

	mr := miniredis.RunT(s.T())
	reg := registry.NewRegistry()
	require.NoError(s.T(), reg.Register(
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("order:export", "导出订单", "订单管理"),
	))
	s.tenantM = tenant.New()
	app, err := rbac.New(
		rbac.WithDB(db),
		rbac.WithPermissionRegistry(reg),
		rbac.WithCache(rediscache.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}))),
		rbac.WithModules(s.tenantM), // tenant 建议首位（迁移顺序）
	)
	require.NoError(s.T(), err)
	s.app = app
	s.mr = mr

	require.NoError(s.T(), app.Migrate(s.ctx))
	_, err = app.SyncPermissions(s.ctx)
	require.NoError(s.T(), err)

	// 平台超管 + 两个租户超管。
	require.NoError(s.T(), app.SeedSuperAdmin(s.ctx, "platform-admin"))
	require.NoError(s.T(), s.tenantM.SeedSuperAdminInTenant(s.ctx, "acme", "acme-admin"))
	require.NoError(s.T(), s.tenantM.SeedSuperAdminInTenant(s.ctx, "beta", "beta-admin"))
}

func (s *IsolationSuite) openDB(name string) *gorm.DB {
	dsn := os.Getenv("RBAC_TEST_MYSQL_DSN")
	admin, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(s.T(), err)
	require.NoError(s.T(), admin.Exec("CREATE DATABASE IF NOT EXISTS "+name+" CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci").Error)
	db, err := gorm.Open(mysql.Open(swapDB(dsn, name)), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(s.T(), err)
	return db
}

func (s *IsolationSuite) tenantCtx(t string) context.Context {
	return core.ContextWithTenant(s.ctx, t)
}

func (s *IsolationSuite) ac(tenantID, subject string) core.AuthorizationContext {
	return core.AuthorizationContext{TenantID: tenantID, SubjectID: core.SubjectID(subject)}
}

// 同 subject、同角色 code 在两个租户各自独立。
func (s *IsolationSuite) TestSameCodeAndSubject_IsolatedPerTenant() {
	// Arrange：acme 与 beta 各建 code='ops' 的角色（跨租户同 code 合法）。
	acmeAdmin := s.ac("acme", "acme-admin")
	betaAdmin := s.ac("beta", "beta-admin")

	_, err := s.app.Roles().Create(s.tenantCtx("acme"), acmeAdmin, "ops", "运营-acme", "")
	s.Require().NoError(err)
	_, err = s.app.Roles().Create(s.tenantCtx("beta"), betaAdmin, "ops", "运营-beta", "")
	s.Require().NoError(err)

	acmeRole, err := s.app.Roles().FindByCode(s.tenantCtx("acme"), "ops")
	s.Require().NoError(err)
	betaRole, err := s.app.Roles().FindByCode(s.tenantCtx("beta"), "ops")
	s.Require().NoError(err)
	s.NotEqual(acmeRole.ID, betaRole.ID)

	s.Require().NoError(s.app.Roles().SetPermissions(s.tenantCtx("acme"), acmeAdmin, acmeRole.ID, []string{"user:list"}))
	s.Require().NoError(s.app.Roles().SetPermissions(s.tenantCtx("beta"), betaAdmin, betaRole.ID, []string{"order:export"}))

	// 同一 subject "10001" 在两个租户各持一个同名角色。
	s.Require().NoError(s.app.UserRoles().Assign(s.tenantCtx("acme"), acmeAdmin, "10001", acmeRole.ID))
	s.Require().NoError(s.app.UserRoles().Assign(s.tenantCtx("beta"), betaAdmin, "10001", betaRole.ID))

	// Act + Assert：授权域隔离。
	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("acme", "10001"), "user:list")
	s.Require().NoError(err)
	s.True(ok, "acme 域内有效")
	ok, err = s.app.Authorizer().HasPermission(s.ctx, s.ac("acme", "10001"), "order:export")
	s.Require().NoError(err)
	s.False(ok, "beta 的权限不得泄漏到 acme")

	ok, err = s.app.Authorizer().HasPermission(s.ctx, s.ac("beta", "10001"), "order:export")
	s.Require().NoError(err)
	s.True(ok)
	ok, err = s.app.Authorizer().HasPermission(s.ctx, s.ac("beta", "10001"), "user:list")
	s.Require().NoError(err)
	s.False(ok, "acme 的权限不得泄漏到 beta")

	// 缓存隔离：两个域的生成键各写各的（§6.1 scope 槽位）。
	_, err = s.app.Authorizer().GetPermissions(s.ctx, s.ac("acme", "10001"))
	s.Require().NoError(err)
	_, err = s.app.Authorizer().GetPermissions(s.ctx, s.ac("beta", "10001"))
	s.Require().NoError(err)
	acmeKeys := keysWithPrefix(s.mr, "rbac:acme:subject:10001:perm:")
	betaKeys := keysWithPrefix(s.mr, "rbac:beta:subject:10001:perm:")
	s.Len(acmeKeys, 1)
	s.Len(betaKeys, 1)
}

// 跨租户角色引用被结构性拒绝（§2.9 跨租户授权保护）。
func (s *IsolationSuite) TestCrossTenantRoleReference_Rejected() {
	// 自包含：本用例自建 beta 角色，避免用例间顺序依赖。
	betaAdmin := s.ac("beta", "beta-admin")
	_, err := s.app.Roles().Create(s.tenantCtx("beta"), betaAdmin, "xrole", "X", "")
	s.Require().NoError(err)
	betaRole, err := s.app.Roles().FindByCode(s.tenantCtx("beta"), "xrole")
	s.Require().NoError(err)
	acmeAdmin := s.ac("acme", "acme-admin")

	// acme 域内引用 beta 的角色 → 拒绝：服务层角色查询按域过滤，
	// 跨域角色直接不可见（仓储层 roleTenantOf 为纵深防御第二层）。
	err = s.app.UserRoles().Assign(s.tenantCtx("acme"), acmeAdmin, "20001", betaRole.ID)
	s.Require().Error(err)
	s.ErrorIs(err, core.ErrRoleNotFound)

	// acme 操作者在 acme 域查 beta 角色 → 不可见（按域过滤）。
	_, err = s.app.Roles().Get(s.tenantCtx("acme"), betaRole.ID)
	s.ErrorIs(err, core.ErrRoleNotFound)
}

// 授权者持权约束在租户域内判定。
func (s *IsolationSuite) TestGrantorConstraint_ScopedPerTenant() {
	// beta 域中 subject 30001 无任何权限。
	err := s.app.Grants().Grant(s.tenantCtx("beta"), s.ac("beta", "30001"), "30002", "order:export", nil, "")
	s.ErrorIs(err, core.ErrGrantorPermissionDenied)
	// 租户超管豁免。
	s.Require().NoError(s.app.Grants().Grant(s.tenantCtx("beta"), s.ac("beta", "beta-admin"), "30003", "order:export", nil, ""))
}

// 平台超管对全部租户生效；租户超管仅本域（§2.9 边界）。
func (s *IsolationSuite) TestSuperAdminBoundaries() {
	// 平台超管以租户上下文访问（空租户上下文按 fail closed 拒绝，见 MissingTenant 用例）。
	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("acme", "platform-admin"), "anything:nope")
	s.Require().NoError(err)
	s.True(ok, "平台超管携带任意租户上下文均恒真")
	isSuper, err := s.app.Authorizer().IsSuperAdministrator(s.ctx, s.ac("beta", "platform-admin"))
	s.Require().NoError(err)
	s.True(isSuper)

	acmeSuper := s.ac("acme", "acme-admin")
	ok, err = s.app.Authorizer().HasPermission(s.ctx, acmeSuper, "anything:nope")
	s.Require().NoError(err)
	s.True(ok, "租户超管本域恒真")
	isSuper, err = s.app.Authorizer().IsSuperAdministrator(s.ctx, s.ac("beta", "acme-admin"))
	s.Require().NoError(err)
	s.False(isSuper, "acme 超管在 beta 域内不是超管")
}

// TenantID 缺失 → fail closed（§2.9）。
func (s *IsolationSuite) TestMissingTenant_FailClosed() {
	_, err := s.app.Authorizer().HasPermission(s.ctx, core.AuthorizationContext{SubjectID: "10001"}, "user:list")
	s.ErrorIs(err, core.ErrTenantRequired)

	// 读路径 ctx 缺租户同样拒绝（隔离仓储 fail closed）。
	_, err = s.app.Roles().Get(s.ctx, 1)
	s.Require().Error(err)
	s.Contains(err.Error(), "tenant scope missing")
}

// 授权撤销在租户域内即时生效（版本递增 + 域内生成键）。
func (s *IsolationSuite) TestGrantRevocation_ScopedImmediate() {
	betaAdmin := s.ac("beta", "beta-admin")
	s.Require().NoError(s.app.Grants().Grant(s.tenantCtx("beta"), betaAdmin, "40001", "order:export", nil, ""))
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("beta", "40001"), "order:export")
	s.True(ok)

	s.Require().NoError(s.app.Grants().Revoke(s.tenantCtx("beta"), betaAdmin, "40001", "order:export"))
	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("beta", "40001"), "order:export")
	s.Require().NoError(err)
	s.False(ok)
}

// keysWithPrefix 过滤 miniredis 全量 key（其 Keys() 不支持通配参数）。
func keysWithPrefix(mr *miniredis.Miniredis, prefix string) []string {
	var out []string
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}
