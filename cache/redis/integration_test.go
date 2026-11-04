// Package redis 集成测试：真实 Redis + 真实 MySQL 上验证 §6 缓存一致性机制。
//
// 环境变量门控（两者都设置才运行）：
//
//	RBAC_TEST_MYSQL_DSN='root:rootpass@tcp(127.0.0.1:3306)/go_rbac_test?parseTime=true&loc=UTC&charset=utf8mb4'
//	RBAC_TEST_REDIS_ADDR=127.0.0.1:6379
//
// make test-integration 自动准备两者（docker compose）。测试独占该 Redis
// 实例（会 FLUSHDB），勿指向生产。
package redis_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

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

type ConsistencySuite struct {
	suite.Suite
	ctx context.Context
	rdb *redis.Client
	db  *gorm.DB
	app *rbac.App
	reg *registry.Registry
}

func TestConsistencySuite(t *testing.T) {
	if os.Getenv("RBAC_TEST_MYSQL_DSN") == "" || os.Getenv("RBAC_TEST_REDIS_ADDR") == "" {
		t.Skip("RBAC_TEST_MYSQL_DSN / RBAC_TEST_REDIS_ADDR not set; skipping consistency tests")
	}
	suite.Run(t, new(ConsistencySuite))
}

func (s *ConsistencySuite) SetupSuite() {
	s.ctx = context.Background()

	rdb := redis.NewClient(&redis.Options{Addr: os.Getenv("RBAC_TEST_REDIS_ADDR")})
	require.NoError(s.T(), rdb.Ping(s.ctx).Err())
	require.NoError(s.T(), rdb.FlushDB(s.ctx).Err())
	s.rdb = rdb

	// 独立数据库：与 gormrepo 集成套件并行运行（go test 多包并行）互不干扰。
	admin, err := gorm.Open(mysql.Open(os.Getenv("RBAC_TEST_MYSQL_DSN")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(s.T(), err)
	require.NoError(s.T(), admin.Exec("CREATE DATABASE IF NOT EXISTS go_rbac_cache_test CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci").Error)
	db, err := gorm.Open(mysql.Open(swapDatabase(os.Getenv("RBAC_TEST_MYSQL_DSN"), "go_rbac_cache_test")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(s.T(), err)
	s.db = db

	for _, t := range []string{
		"schema_migrations", "rbac_user_grants", "rbac_role_permissions",
		"rbac_user_roles", "rbac_permissions", "rbac_roles",
	} {
		require.NoError(s.T(), db.Exec("DROP TABLE IF EXISTS "+t).Error)
	}

	s.reg = registry.NewRegistry()
	require.NoError(s.T(), s.reg.Register(
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("user:delete", "删除用户", "用户管理"),
		registry.New("order:export", "导出订单", "订单管理"),
	))

	app, err := rbac.New(
		rbac.WithDB(db),
		rbac.WithPermissionRegistry(s.reg),
		rbac.WithCache(rediscache.New(rdb)),
		rbac.WithCacheTTL(10*time.Minute),
	)
	require.NoError(s.T(), err)
	s.app = app

	require.NoError(s.T(), app.Migrate(s.ctx))
	_, err = app.SyncPermissions(s.ctx)
	require.NoError(s.T(), err)
	require.NoError(s.T(), app.SeedSuperAdmin(s.ctx, "root-admin"))
}

func (s *ConsistencySuite) SetupTest() {
	// 每个用例清空缓存与授权关系，保证隔离；保留超管绑定（grantor 约束豁免依赖它）。
	require.NoError(s.T(), s.rdb.FlushDB(s.ctx).Err())
	require.NoError(s.T(), s.db.Exec(
		"DELETE FROM rbac_user_roles WHERE role_id NOT IN (SELECT id FROM rbac_roles WHERE code = ?)",
		model.BuiltinSuperAdminRoleCode,
	).Error)
	require.NoError(s.T(), s.db.Exec(
		"DELETE FROM rbac_role_permissions WHERE role_id NOT IN (SELECT id FROM rbac_roles WHERE code = ?)",
		model.BuiltinSuperAdminRoleCode,
	).Error)
	require.NoError(s.T(), s.db.Where("code != ?", model.BuiltinSuperAdminRoleCode).Delete(&model.Role{}).Error)
	// 恢复权限状态（用例可能禁用过）与用户授权历史。
	require.NoError(s.T(), s.db.Exec("UPDATE rbac_permissions SET status = ?", model.PermissionStatusEnabled).Error)
	require.NoError(s.T(), s.db.Exec("DELETE FROM rbac_user_grants").Error)
}

var (
	admin = core.AuthorizationContext{SubjectID: "root-admin"}
	user  = core.AuthorizationContext{SubjectID: "90001"}
)

// swapDatabase 替换 DSN 中的数据库名（user:pass@tcp(host)/db?params 形态）。
func swapDatabase(dsn, newDB string) string {
	q := ""
	if i := strings.Index(dsn, "?"); i >= 0 {
		dsn, q = dsn[:i], dsn[i:]
	}
	if i := strings.LastIndex(dsn, "/"); i >= 0 {
		return dsn[:i+1] + newDB + q
	}
	return dsn
}

func (s *ConsistencySuite) roleWithPerms(code string, perms ...string) *model.Role {
	role, err := s.app.Roles().Create(s.ctx, admin, code, code, "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(s.ctx, admin, role.ID, perms))
	return role
}

// §6.3 行 1：用户角色变更 → 递增该用户版本 → 撤销即时生效。
func (s *ConsistencySuite) TestUserRoleChange_InvalidatesImmediately() {
	role := s.roleWithPerms("cache_r1", "user:list")
	s.Require().NoError(s.app.UserRoles().Assign(s.ctx, admin, "90001", role.ID))

	ok, err := s.app.Authorizer().HasPermission(s.ctx, user, "user:list")
	s.Require().NoError(err)
	s.True(ok, "首次读取（回源并缓存）")

	s.Require().NoError(s.app.UserRoles().Revoke(s.ctx, admin, "90001", role.ID))

	ok, err = s.app.Authorizer().HasPermission(s.ctx, user, "user:list")
	s.Require().NoError(err)
	s.False(ok, "撤销后必须立即失效（版本递增 + 新生成键）")
}

// §6.3 行 3：角色权限变更 → 批量递增关联用户版本。
func (s *ConsistencySuite) TestRolePermissionChange_InvalidatesRoleSubjects() {
	role := s.roleWithPerms("cache_r2", "user:list")
	s.Require().NoError(s.app.UserRoles().Assign(s.ctx, admin, "90001", role.ID))

	ok, _ := s.app.Authorizer().HasPermission(s.ctx, user, "user:list")
	s.Require().True(ok)

	// 角色权限收缩：移除 user:list（空集合替换）。
	s.Require().NoError(s.app.Roles().SetPermissions(s.ctx, admin, role.ID, nil))

	ok, err := s.app.Authorizer().HasPermission(s.ctx, user, "user:list")
	s.Require().NoError(err)
	s.False(ok, "角色权限变更必须批量失效关联用户")
}

// §6.3 行 4：角色禁用 → 批量递增关联用户版本。
func (s *ConsistencySuite) TestRoleDisable_InvalidatesRoleSubjects() {
	role := s.roleWithPerms("cache_r3", "user:list")
	s.Require().NoError(s.app.UserRoles().Assign(s.ctx, admin, "90001", role.ID))

	ok, _ := s.app.Authorizer().HasPermission(s.ctx, user, "user:list")
	s.Require().True(ok)

	s.Require().NoError(s.app.Roles().SetStatus(s.ctx, admin, role.ID, model.RoleStatusDisabled))

	ok, err := s.app.Authorizer().HasPermission(s.ctx, user, "user:list")
	s.Require().NoError(err)
	s.False(ok, "角色禁用必须批量失效关联用户")
}

// §6.3 行 2/行 5：用户额外授权与权限禁用（epoch 全局失效）。
func (s *ConsistencySuite) TestGrantLifecycle_AndEpochInvalidation() {
	// 授权即时生效。
	s.Require().NoError(s.app.Grants().Grant(s.ctx, admin, "90001", "order:export", nil, "临时"))
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, user, "order:export")
	s.Require().True(ok)

	// 撤销即时生效（版本递增）。
	s.Require().NoError(s.app.Grants().Revoke(s.ctx, admin, "90001", "order:export"))
	ok, err := s.app.Authorizer().HasPermission(s.ctx, user, "order:export")
	s.Require().NoError(err)
	s.False(ok)

	// 重新授权后，权限禁用（epoch）使全部缓存失效。
	s.Require().NoError(s.app.Grants().Grant(s.ctx, admin, "90001", "order:export", nil, "再次"))
	ok, _ = s.app.Authorizer().HasPermission(s.ctx, user, "order:export")
	s.Require().True(ok)

	s.Require().NoError(s.app.Permissions().SetStatus(s.ctx, admin, "order:export", model.PermissionStatusDisabled))
	ok, err = s.app.Authorizer().HasPermission(s.ctx, user, "order:export")
	s.Require().NoError(err)
	s.False(ok, "权限禁用 → INCR epoch → 全员生成键失效")
}

// §6.5：临时授权到期后缓存不得继续放行（TTL 上限 + 查询时校验双保险）。
func (s *ConsistencySuite) TestTemporaryGrantExpiry() {
	// 直接落库一条 2 秒后到期的授权并递增版本。
	expiry := time.Now().UTC().Add(2 * time.Second)
	s.Require().NoError(s.app.Grants().Grant(s.ctx, admin, "90001", "order:export", &expiry, "临时"))

	ok, _ := s.app.Authorizer().HasPermission(s.ctx, user, "order:export")
	s.Require().True(ok, "到期前可用")

	time.Sleep(2200 * time.Millisecond)

	ok, err := s.app.Authorizer().HasPermission(s.ctx, user, "order:export")
	s.Require().NoError(err)
	s.False(ok, "到期后必须失效（查询层校验兜底）")
}

// §6.2 命中路径：缓存条目确实写入且带 TTL。
func (s *ConsistencySuite) TestCacheEntriesWrittenWithTTL() {
	role := s.roleWithPerms("cache_r4", "user:list")
	s.Require().NoError(s.app.UserRoles().Assign(s.ctx, admin, "90001", role.ID))

	_, err := s.app.Authorizer().GetPermissions(s.ctx, user)
	s.Require().NoError(err)

	keys := s.rdb.Keys(s.ctx, "rbac:default:subject:90001:perm:*").Val()
	s.Require().Len(keys, 1, "恰好一个生成键")
	ttl := s.rdb.TTL(s.ctx, keys[0]).Val()
	s.Greater(ttl, time.Duration(0))
	s.LessOrEqual(ttl, 10*time.Minute, "TTL 不超过配置上限")
}

// §9.4 性能基线（准入基线而非 SLA）。
func (s *ConsistencySuite) TestPerformanceBaselines() {
	// 命中路径 P99 < 1ms（不含框架开销）。
	role := s.roleWithPerms("cache_perf", "user:list")
	s.Require().NoError(s.app.UserRoles().Assign(s.ctx, admin, "90001", role.ID))
	_, err := s.app.Authorizer().HasPermission(s.ctx, user, "user:list")
	s.Require().NoError(err)

	const n = 1000
	latencies := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		ok, err := s.app.Authorizer().HasPermission(s.ctx, user, "user:list")
		s.Require().NoError(err)
		s.Require().True(ok)
		latencies = append(latencies, time.Since(start))
	}
	p99 := percentile(latencies, 0.99)
	s.Less(p99, time.Millisecond, "缓存命中路径 P99 < 1ms（实测 P99=%s）", p99)
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	// 简易选择（输入未排序也能工作）：排序后取分位。
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}
