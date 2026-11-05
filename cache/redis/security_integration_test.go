// 安全测试套件（§9.3 清单）：真实 MySQL + 进程内 Redis（miniredis）。
// 环境变量门控：RBAC_TEST_MYSQL_DSN（独立数据库 go_rbac_sec_test）。
package redis_test

import (
	"context"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/animacaeli/go-rbac"
	rediscache "github.com/animacaeli/go-rbac/cache/redis"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// SecuritySuite 逐条覆盖 §9.3 中需要数据库/缓存基础设施的项；
// 纯适配器/服务层的项（身份解析失败 401、数据库异常 fail closed 等）
// 已在对应单元测试中覆盖，此处不重复。
type SecuritySuite struct {
	suite.Suite
	ctx context.Context
	db  *gorm.DB
	mr  *miniredis.Miniredis
	app *rbac.App
	reg *registry.Registry
}

func TestSecuritySuite(t *testing.T) {
	if os.Getenv("RBAC_TEST_MYSQL_DSN") == "" {
		t.Skip("RBAC_TEST_MYSQL_DSN not set; skipping security tests")
	}
	suite.Run(t, new(SecuritySuite))
}

func (s *SecuritySuite) SetupSuite() {
	s.ctx = context.Background()
	dsn := os.Getenv("RBAC_TEST_MYSQL_DSN")
	admin, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(s.T(), err)
	require.NoError(s.T(), admin.Exec("CREATE DATABASE IF NOT EXISTS go_rbac_sec_test CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci").Error)
	db, err := gorm.Open(mysql.Open(swapDatabase(dsn, "go_rbac_sec_test")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(s.T(), err)
	for _, t := range []string{
		"schema_migrations", "rbac_user_grants", "rbac_role_permissions",
		"rbac_user_roles", "rbac_permissions", "rbac_roles",
	} {
		require.NoError(s.T(), db.Exec("DROP TABLE IF EXISTS "+t).Error)
	}
	s.db = db

	s.mr = miniredis.RunT(s.T())
	s.reg = registry.NewRegistry()
	require.NoError(s.T(), s.reg.Register(
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("rbac_test:secret", "机密操作", "测试"),
	))
	app, err := rbac.New(
		rbac.WithDB(db),
		rbac.WithPermissionRegistry(s.reg),
		rbac.WithCache(rediscache.New(redis.NewClient(&redis.Options{Addr: s.mr.Addr()}))),
	)
	require.NoError(s.T(), err)
	s.app = app
	require.NoError(s.T(), app.Migrate(s.ctx))
	_, err = app.SyncPermissions(s.ctx)
	require.NoError(s.T(), err)
	require.NoError(s.T(), app.SeedSuperAdmin(s.ctx, "sec-admin"))
}

var (
	secAdmin = core.AuthorizationContext{SubjectID: "sec-admin"}
	secUser  = core.AuthorizationContext{SubjectID: "90001"}
)

// §9.3：无权限不能访问（且缓存不得放大错误授权）。
func (s *SecuritySuite) TestNoPermission_Denied_EvenWithCacheWarm() {
	role, err := s.app.Roles().Create(s.ctx, secAdmin, "sec_role", "R", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(s.ctx, secAdmin, role.ID, []string{"user:list"}))
	s.Require().NoError(s.app.UserRoles().Assign(s.ctx, secAdmin, "90001", role.ID))

	// 预热缓存（持有 user:list）。
	ok, err := s.app.Authorizer().HasPermission(s.ctx, secUser, "user:list")
	s.Require().NoError(err)
	s.True(ok)

	// 未持有的权限必须拒绝（缓存命中路径同样拒绝）。
	ok, err = s.app.Authorizer().HasPermission(s.ctx, secUser, "rbac_test:secret")
	s.Require().NoError(err)
	s.False(ok)
}

// §9.3：普通管理员不能越权授予（含 rbac:* 与超管角色）。
func (s *SecuritySuite) TestPrivilegeEscalation_Blocked() {
	// 普通管理员（仅持有 user:list）尝试授予自己不持有的权限。
	role, err := s.app.Roles().Create(s.ctx, secAdmin, "esc_role", "E", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(s.ctx, secAdmin, role.ID, []string{"user:list"}))
	s.Require().NoError(s.app.UserRoles().Assign(s.ctx, secAdmin, "90002", role.ID))
	notHolder := core.AuthorizationContext{SubjectID: "90002"}

	// 越权授予业务权限。
	err = s.app.Grants().Grant(s.ctx, notHolder, "90003", "rbac_test:secret", nil, "")
	s.Require().ErrorIs(err, core.ErrGrantorPermissionDenied)

	// 越权授予内置 rbac:* 管理权限。
	err = s.app.Grants().Grant(s.ctx, notHolder, "90003", "rbac:role:create", nil, "")
	s.Require().ErrorIs(err, core.ErrGrantorPermissionDenied)

	// 分配含未持有权限的角色。
	esc2, err := s.app.Roles().Create(s.ctx, secAdmin, "esc2", "E2", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(s.ctx, secAdmin, esc2.ID, []string{"rbac_test:secret"}))
	err = s.app.UserRoles().Assign(s.ctx, notHolder, "90003", esc2.ID)
	s.Require().ErrorIs(err, core.ErrGrantorPermissionDenied)

	// 直接分配超管角色：内置保护拒绝。
	superRole, err := s.app.Roles().FindByCode(s.ctx, model.BuiltinSuperAdminRoleCode)
	s.Require().NoError(err)
	err = s.app.UserRoles().Assign(s.ctx, secAdmin, "90003", superRole.ID)
	s.Require().ErrorIs(err, core.ErrBuiltinRoleProtected)

	// 给自己提权：修改自己角色加上未持有权限。
	err = s.app.Roles().SetPermissions(s.ctx, notHolder, role.ID, []string{"user:list", "rbac_test:secret"})
	s.Require().ErrorIs(err, core.ErrGrantorPermissionDenied)
}

// §9.3：内置受保护角色不可经管理接口修改。
func (s *SecuritySuite) TestBuiltinRole_ModificationsBlocked() {
	superRole, err := s.app.Roles().FindByCode(s.ctx, model.BuiltinSuperAdminRoleCode)
	s.Require().NoError(err)

	s.Require().ErrorIs(s.app.Roles().Delete(s.ctx, secAdmin, superRole.ID), core.ErrBuiltinRoleProtected)
	s.Require().ErrorIs(s.app.Roles().SetStatus(s.ctx, secAdmin, superRole.ID, model.RoleStatusDisabled), core.ErrBuiltinRoleProtected)
	s.Require().ErrorIs(s.app.Roles().SetPermissions(s.ctx, secAdmin, superRole.ID, []string{"user:list"}), core.ErrBuiltinRoleProtected)
	// P1-01（外部评审第七轮）：撤销超管角色绑定同样被拒。
	s.Require().ErrorIs(s.app.UserRoles().Revoke(s.ctx, secAdmin, "sec-admin", superRole.ID), core.ErrBuiltinRoleProtected)

	// 撤销被拒后超管身份不受影响。
	isSuper, err := s.app.Authorizer().IsSuperAdministrator(s.ctx, secAdmin)
	s.Require().NoError(err)
	s.True(isSuper)
}

// §9.3 + §6.6：Redis 异常——鉴权路径回源数据库保持正确（不得错误放行或错误拒绝）；
// 管理接口的失效递增失败 → 操作整体报错（权限管理在 Redis 故障期间不可用）。
func (s *SecuritySuite) TestRedisOutage_Semantics() {
	// Arrange：正常授权一笔，确认可用。
	s.Require().NoError(s.app.Grants().Grant(s.ctx, secAdmin, "90004", "user:list", nil, ""))
	ok, err := s.app.Authorizer().HasPermission(s.ctx, core.AuthorizationContext{SubjectID: "90004"}, "user:list")
	s.Require().NoError(err)
	s.True(ok)

	// Act：模拟 Redis 整体故障。
	s.mr.SetError("redis unavailable")

	// Assert：鉴权回源数据库，结果正确（fail closed 不等于错误拒绝）。
	ok, err = s.app.Authorizer().HasPermission(s.ctx, core.AuthorizationContext{SubjectID: "90004"}, "user:list")
	s.Require().NoError(err)
	s.True(ok, "Redis 故障时鉴权回源主库，不得错误放行/拒绝")
	ok, err = s.app.Authorizer().HasPermission(s.ctx, core.AuthorizationContext{SubjectID: "90004"}, "rbac_test:secret")
	s.Require().NoError(err)
	s.False(ok)

	// 授权变更：版本递增失败 → 整体报错（不得返回成功）。
	err = s.app.Grants().Grant(s.ctx, secAdmin, "90005", "user:list", nil, "")
	s.Require().Error(err, "Redis 故障期间管理接口必须报错而非假成功")
	s.Contains(err.Error(), "redis")

	// 恢复后管理接口立即可用。
	s.mr.SetError("")
	s.Require().NoError(s.app.Grants().Grant(s.ctx, secAdmin, "90005", "user:list", nil, ""))
}
