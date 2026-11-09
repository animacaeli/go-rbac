// Package tenant 集成测试：迁移契约（§5.5，模块第一验收项）与双租户隔离。
//
// 环境变量门控：RBAC_TEST_MYSQL_DSN（使用独立数据库 go_rbac_tenant_test，
// 与其他集成套件并行互不干扰）。
package tenant_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/animacaeli/go-rbac"
	rediscache "github.com/animacaeli/go-rbac/cache/redis"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/modules/audit"
	"github.com/animacaeli/go-rbac/modules/datascope"
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

// SetupTest 每个用例都从空库开始："升级路径"与"全新路径"互不污染。
func (s *MigrationContractSuite) SetupTest() {
	for _, t := range []string{
		"schema_migrations", "rbac_user_grants", "rbac_role_permissions",
		"rbac_user_roles", "rbac_permissions", "rbac_roles", "rbac_counters",
	} {
		require.NoError(s.T(), s.db.Exec("DROP TABLE IF EXISTS "+t).Error)
	}
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
	// Core 0001–0004 + tenant 0001。
	s.Equal([]string{"0001", "0002", "0003", "0004", "0001"}, versions)
}

// 部分失败恢复：DDL 已隐式提交、版本行未写入（进程崩溃窗口）时，重跑必须成功。
func (s *MigrationContractSuite) TestContract_TenantMigration_ReentrantAfterVersionRowLoss() {
	app := s.newApp(true)
	require.NoError(s.T(), app.Migrate(s.ctx))

	// 构造病态中间态：新旧唯一键同时存在（旧实现的 DROP+ADD 若被拆开执行
	// 就可能留下这种状态），重跑必须清理旧键。
	require.NoError(s.T(), s.db.Exec(
		"ALTER TABLE rbac_roles ADD UNIQUE KEY uk_code (code)").Error)

	// 模拟"全部 DDL 已提交、tenant/0001 版本行未落库"的崩溃窗口。
	require.NoError(s.T(), s.db.Exec(
		"DELETE FROM schema_migrations WHERE module = 'tenant' AND version = '0001'").Error)

	// 旧实现会在 ADD COLUMN 上撞 1060 duplicate column，永久卡死。
	require.NoError(s.T(), app.Migrate(s.ctx), "部分失败后重跑必须成功（幂等 DDL）")

	var n int64
	require.NoError(s.T(), s.db.Table("schema_migrations").
		Where("module = 'tenant' AND version = '0001'").Count(&n).Error)
	s.Equal(int64(1), n, "版本行应重新写入")

	// 旧唯一键必须被清理（否则同 code 跨租户仍被拒绝）。
	var oldKey int64
	require.NoError(s.T(), s.db.Raw(
		"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'rbac_roles' AND index_name = 'uk_code'",
	).Scan(&oldKey).Error)
	s.Zero(oldKey, "遗留的 uk_code 必须被清理")

	// 唯一键仍为租户维度：同 code 跨租户可行、同租户内唯一。
	require.NoError(s.T(), s.db.Exec(
		"INSERT INTO rbac_roles (tenant_id, code, name, status, created_at, updated_at) VALUES ('acme', 'replay', 'A', 1, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))").Error)
	require.NoError(s.T(), s.db.Exec(
		"INSERT INTO rbac_roles (tenant_id, code, name, status, created_at, updated_at) VALUES ('beta', 'replay', 'B', 1, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))").Error)
}

// 并发迁移：GET_LOCK 串行化，两个实例同时启动都应成功。
func (s *MigrationContractSuite) TestContract_ConcurrentMigrate_Serialized() {
	app1 := s.newApp(true)
	app2 := s.newApp(true)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = app1.Migrate(s.ctx) }()
	go func() { defer wg.Done(); errs[1] = app2.Migrate(s.ctx) }()
	wg.Wait()
	require.NoError(s.T(), errs[0], "并发迁移实例 1")
	require.NoError(s.T(), errs[1], "并发迁移实例 2")
}

// IsolationSuite 双租户隔离验证（§2.9 承担项）。
type IsolationSuite struct {
	suite.Suite
	ctx     context.Context
	db      *gorm.DB
	mr      *miniredis.Miniredis
	app     *rbac.App
	tenantM *tenant.Module
	ds      *datascope.Module
	auditM  *audit.Module
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
		"schema_migrations", "rbac_audit_logs", "rbac_role_data_scopes", "rbac_user_grants",
		"rbac_role_permissions", "rbac_user_roles", "rbac_permissions", "rbac_roles", "rbac_counters",
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
	s.ds = datascope.New()
	s.auditM = audit.New()
	app, err := rbac.New(
		rbac.WithDB(db),
		rbac.WithPermissionRegistry(reg),
		rbac.WithCache(rediscache.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}))),
		rbac.WithModules(s.tenantM, s.ds, s.auditM), // tenant 建议首位（迁移顺序）
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

// P1-4 专项：管理接口按租户过滤——跨租户不可见、不可操作（含直传 ID 路径）。
func (s *IsolationSuite) TestManagementSurface_TenantFiltered() {
	betaAdmin := s.ac("beta", "beta-admin")
	acmeAdmin := s.ac("acme", "acme-admin")

	// beta 建角色；acme 的 List 不可见。
	_, err := s.app.Roles().Create(s.tenantCtx("beta"), betaAdmin, "vis_role", "V", "")
	s.Require().NoError(err)
	acmeRoles, err := s.app.Roles().List(s.tenantCtx("acme"), rbac.RoleFilter{})
	s.Require().NoError(err)
	for _, r := range acmeRoles {
		s.NotEqual("vis_role", r.Code, "acme 角色列表不得泄漏 beta 角色")
	}

	// 直传 beta 角色 ID 到 acme 域操作（SetPermissions）→ 不可见即拒绝。
	betaRole, err := s.app.Roles().FindByCode(s.tenantCtx("beta"), "vis_role")
	s.Require().NoError(err)
	err = s.app.Roles().SetPermissions(s.tenantCtx("acme"), acmeAdmin, betaRole.ID, []string{"user:list"})
	s.Require().ErrorIs(err, core.ErrRoleNotFound)

	// Grant/Revoke 同样以域过滤（acme 域内查无 beta 主体授权可撤销）。
	err = s.app.Grants().Revoke(s.tenantCtx("acme"), acmeAdmin, "10001", "user:list")
	s.ErrorIs(err, core.ErrGrantNotFound, "acme 域内的撤销不得影响 beta 域数据")
}

// 第四轮审核回归：租户域的权威计数器必须在变更事务内递增（键含租户前缀）。
// 修复前：base bump 硬编码 default:，tenant 覆写无 bump → 租户权威永不前进，
// 副本丢失后从 DB 恢复会把生成键回退到陈旧值（旧权限复活条件成立）。
func (s *IsolationSuite) TestTenantAuthorityCounters_BumpPerScope() {
	// Arrange：acme 域内授权（走 tenant 仓储覆写）。
	acmeAdmin := s.ac("acme", "acme-admin")
	s.Require().NoError(s.app.Grants().Grant(s.tenantCtx("acme"), acmeAdmin, "99001", "order:export", nil, ""))

	// Assert：rbac_counters 必须出现 acme 前缀的主体版本键，值 ≥1。
	var v int64
	err := s.db.Table("rbac_counters").
		Select("v").
		Where("k = ?", "acme:subject:99001:version").
		Limit(1).
		Scan(&v).Error
	s.Require().NoError(err)
	s.GreaterOrEqual(v, int64(1), "租户域授权必须在同事务递增 acme: 主体版本（修复前此键不存在）")

	// 角色级操作（走共享 base SetPermissions，scope 取自 ctx）递增 acme:epoch。
	role, err := s.app.Roles().Create(s.tenantCtx("acme"), acmeAdmin, "cnt_role", "C", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(s.tenantCtx("acme"), acmeAdmin, role.ID, []string{"order:export"}))
	var e int64
	s.Require().NoError(s.db.Table("rbac_counters").
		Select("v").Where("k = ?", "acme:epoch").Limit(1).Scan(&e).Error)
	s.GreaterOrEqual(e, int64(1), "租户域角色级变更必须递增 acme:epoch")
}

// 角色禁用必须立即失效本租户缓存（§6.3：角色级变更 → 授权域 epoch 同事务递增）。
// 旧实现的 tenant 仓储漏了 epoch 递增，禁用角色后旧权限仍从缓存放行至 TTL。
func (s *IsolationSuite) TestRoleDisabled_InvalidatesTenantCache() {
	acmeCtx := s.tenantCtx("acme")
	acmeAdmin := s.ac("acme", "acme-admin")
	role, err := s.app.Roles().Create(acmeCtx, acmeAdmin, "r_disable", "待禁用", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(acmeCtx, acmeAdmin, role.ID, []string{"user:list"}))
	s.Require().NoError(s.app.UserRoles().Assign(acmeCtx, acmeAdmin, "u_disable", role.ID))

	ac := s.ac("acme", "u_disable")
	ok, err := s.app.Authorizer().HasPermission(s.ctx, ac, "user:list")
	s.Require().NoError(err)
	s.Require().True(ok, "预热缓存")

	s.Require().NoError(s.app.Roles().SetStatus(acmeCtx, acmeAdmin, role.ID, model.RoleStatusDisabled))

	ok, err = s.app.Authorizer().HasPermission(s.ctx, ac, "user:list")
	s.Require().NoError(err)
	s.False(ok, "禁用角色后旧权限必须立即失效")
}

// 权限表是全局定义：任一租户禁用权限，必须让所有租户域的缓存一起失效。
func (s *IsolationSuite) TestGlobalPermissionDisabled_InvalidatesAllTenants() {
	acmeCtx, betaCtx := s.tenantCtx("acme"), s.tenantCtx("beta")
	acmeAdmin, betaAdmin := s.ac("acme", "acme-admin"), s.ac("beta", "beta-admin")

	acmeRole, err := s.app.Roles().Create(acmeCtx, acmeAdmin, "r_gp_acme", "A", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(acmeCtx, acmeAdmin, acmeRole.ID, []string{"order:export"}))
	s.Require().NoError(s.app.UserRoles().Assign(acmeCtx, acmeAdmin, "u_gp_acme", acmeRole.ID))

	betaRole, err := s.app.Roles().Create(betaCtx, betaAdmin, "r_gp_beta", "B", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(betaCtx, betaAdmin, betaRole.ID, []string{"order:export"}))
	s.Require().NoError(s.app.UserRoles().Assign(betaCtx, betaAdmin, "u_gp_beta", betaRole.ID))

	acmeAC := s.ac("acme", "u_gp_acme")
	betaAC := s.ac("beta", "u_gp_beta")
	ok, err := s.app.Authorizer().HasPermission(s.ctx, acmeAC, "order:export")
	s.Require().NoError(err)
	s.Require().True(ok)
	ok, err = s.app.Authorizer().HasPermission(s.ctx, betaAC, "order:export")
	s.Require().NoError(err)
	s.Require().True(ok, "预热 beta 缓存")

	s.T().Cleanup(func() {
		_ = s.app.Permissions().SetStatus(acmeCtx, acmeAdmin, "order:export", model.PermissionStatusEnabled)
	})
	s.Require().NoError(s.app.Permissions().SetStatus(acmeCtx, acmeAdmin, "order:export", model.PermissionStatusDisabled))

	ok, err = s.app.Authorizer().HasPermission(s.ctx, acmeAC, "order:export")
	s.Require().NoError(err)
	s.False(ok, "acme：权限已禁用")
	ok, err = s.app.Authorizer().HasPermission(s.ctx, betaAC, "order:export")
	s.Require().NoError(err)
	s.False(ok, "beta：全局权限禁用必须跨租户失效（旧实现会继续放行）")
}

// 数据范围按租户隔离：同一 subject_id 在两个租户持有不同角色时，
// 不得把 A 租户配置的宽范围泄漏给 B 租户。
func (s *IsolationSuite) TestDataScope_IsolatedPerTenant() {
	acmeCtx, betaCtx := s.tenantCtx("acme"), s.tenantCtx("beta")
	acmeAdmin, betaAdmin := s.ac("acme", "acme-admin"), s.ac("beta", "beta-admin")

	acmeRole, err := s.app.Roles().Create(acmeCtx, acmeAdmin, "ds_acme", "A", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.UserRoles().Assign(acmeCtx, acmeAdmin, "shared-user", acmeRole.ID))
	s.Require().NoError(s.ds.SetRoleScope(acmeCtx, acmeAdmin, acmeRole.ID, "order", datascope.ScopeAll))

	betaRole, err := s.app.Roles().Create(betaCtx, betaAdmin, "ds_beta", "B", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.UserRoles().Assign(betaCtx, betaAdmin, "shared-user", betaRole.ID))

	acmeScope, err := s.ds.ResolveDataScope(s.ctx, s.ac("acme", "shared-user"), "order")
	s.Require().NoError(err)
	s.Equal(datascope.ScopeAll, acmeScope)

	betaScope, err := s.ds.ResolveDataScope(s.ctx, s.ac("beta", "shared-user"), "order")
	s.Require().NoError(err)
	s.Equal(datascope.ScopeSelf, betaScope, "acme 的 ScopeAll 不得泄漏到 beta")

	// 跨租户改写被结构性拒绝（角色 ID 全局唯一，必须按租户过滤）。
	err = s.ds.SetRoleScope(betaCtx, betaAdmin, acmeRole.ID, "order", datascope.ScopeSelf)
	s.Require().Error(err)
	s.True(errors.Is(err, repository.ErrRecordNotFound), "beta 不得改写 acme 角色的数据范围: %v", err)
}

// 启用多租户后，管理服务的 operator.TenantID 必填：空租户会静默写入平台域。
func (s *IsolationSuite) TestManagement_EmptyOperatorTenantFailsClosed() {
	noTenant := core.AuthorizationContext{SubjectID: "acme-admin"}

	_, err := s.app.Roles().Create(s.ctx, noTenant, "r_platform_leak", "P", "")
	s.ErrorIs(err, core.ErrTenantRequired)

	err = s.app.Grants().Grant(s.ctx, noTenant, "someone", "order:export", nil, "")
	s.ErrorIs(err, core.ErrTenantRequired)

	// 平台域不得出现该角色（证明检查发生在落库之前）。
	var n int64
	s.Require().NoError(s.db.Table("rbac_roles").
		Where("tenant_id = ? AND code = ?", "", "r_platform_leak").Count(&n).Error)
	s.Zero(n, "空租户 operator 不得在平台域创建角色")
}

// 多租户下审计查询必须显式指定授权域（fail closed），不得退化为全租户查询。
func (s *IsolationSuite) TestAuditQuery_RequiresTenantContext() {
	q := audit.NewQuery(s.auditM)

	_, err := q.List(s.ctx, audit.Filter{})
	s.ErrorIs(err, core.ErrTenantRequired)

	_, err = q.List(s.tenantCtx("acme"), audit.Filter{})
	s.NoError(err)
}

// 审计查询的租户边界：默认只允许当前请求租户；跨租户与平台域查询必须
// 使用 WithCrossTenantAccess（平台级授权端点专用构造）。
func (s *IsolationSuite) TestAuditQuery_TenantBoundary() {
	acmeCtx, betaCtx := s.tenantCtx("acme"), s.tenantCtx("beta")
	acme, beta, platform := "acme", "beta", ""
	q := audit.NewQuery(s.auditM)

	// A 查 A：允许（显式指定同一租户亦允许）。
	_, err := q.List(acmeCtx, audit.Filter{})
	s.NoError(err)
	_, err = q.List(acmeCtx, audit.Filter{Tenant: &acme})
	s.NoError(err)

	// A 查 B、B 查 A、租户查平台域：一律拒绝。
	_, err = q.List(acmeCtx, audit.Filter{Tenant: &beta})
	s.ErrorIs(err, audit.ErrTenantScopeViolation)
	_, err = q.List(betaCtx, audit.Filter{Tenant: &acme})
	s.ErrorIs(err, audit.ErrTenantScopeViolation)
	_, err = q.List(acmeCtx, audit.Filter{Tenant: &platform})
	s.ErrorIs(err, audit.ErrTenantScopeViolation)

	// 平台级授权端点（显式构造）：允许跨租户与平台域查询。
	adminQ := audit.NewQuery(s.auditM, audit.WithCrossTenantAccess())
	_, err = adminQ.List(acmeCtx, audit.Filter{Tenant: &beta})
	s.NoError(err)
	_, err = adminQ.List(acmeCtx, audit.Filter{Tenant: &platform})
	s.NoError(err)
}

// 租户超管种子必须在落库前完成完整租户标识校验。
func (s *IsolationSuite) TestSeedSuperAdminInTenant_ValidatesTenantID() {
	for _, bad := range []string{"", "default", "!global", "tenant/a", "tenant a"} {
		err := s.tenantM.SeedSuperAdminInTenant(s.ctx, bad, "seed-subject")
		s.Error(err, "非法租户标识必须拒绝: %q", bad)
		s.ErrorIs(err, core.ErrInvalidTenantID, "错误应可识别: %q", bad)
	}

	// 非法标识不得留下任何角色行（default / !global / 非法字符）。
	var n int64
	s.Require().NoError(s.db.Table("rbac_roles").
		Where("tenant_id IN ?", []string{"default", "!global", "tenant/a", "tenant a"}).Count(&n).Error)
	s.Zero(n, "校验必须发生在任何数据库写入之前")

	// 合法标识可用。
	s.NoError(s.tenantM.SeedSuperAdminInTenant(s.ctx, "tenant_a", "seed-a"))
	s.NoError(s.tenantM.SeedSuperAdminInTenant(s.ctx, "tenant-001", "seed-b"))
}
