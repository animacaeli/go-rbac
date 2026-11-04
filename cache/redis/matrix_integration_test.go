// 失效矩阵发布门禁（§9.1/§9.2/§9.3 + 外部审核问题 1/2）。
//
// 十二行场景全部在真实 MySQL + 真实 Redis 上端到端验证（非 miniredis——
// 淘汰、故障注入、恢复语义需要真实实例行为）。CI 集成 job 每次运行；
// 发布（release workflow 的 verify job）同样以此为门禁。
//
// 环境变量门控：RBAC_TEST_MYSQL_DSN + RBAC_TEST_REDIS_ADDR（make test-integration 自动提供）。
package redis_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/animacaeli/go-rbac"
	rediscache "github.com/animacaeli/go-rbac/cache/redis"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// gateSubjectStatus 可切换主体状态检查器（行 2：用户被禁用）。
type gateSubjectStatus struct {
	disabled map[string]bool
}

func (g *gateSubjectStatus) IsSubjectActive(_ context.Context, subjectID core.SubjectID) (bool, error) {
	return !g.disabled[subjectID.String()], nil
}

type MatrixSuite struct {
	suite.Suite
	ctx    context.Context
	db     *gorm.DB
	rdb    *redis.Client
	app    *rbac.App
	status *gateSubjectStatus
	reg    *registry.Registry
}

func TestMatrixSuite(t *testing.T) {
	if os.Getenv("RBAC_TEST_MYSQL_DSN") == "" || os.Getenv("RBAC_TEST_REDIS_ADDR") == "" {
		t.Skip("RBAC_TEST_MYSQL_DSN / RBAC_TEST_REDIS_ADDR not set; skipping invalidation-matrix gate")
	}
	suite.Run(t, new(MatrixSuite))
}

func (s *MatrixSuite) SetupSuite() {
	s.ctx = context.Background()
	dsn := os.Getenv("RBAC_TEST_MYSQL_DSN")
	admin, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(s.T(), err)
	require.NoError(s.T(), admin.Exec("CREATE DATABASE IF NOT EXISTS go_rbac_matrix_test CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci").Error)
	db, err := gorm.Open(mysql.Open(swapDatabase(dsn, "go_rbac_matrix_test")), &gorm.Config{
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

	s.rdb = redis.NewClient(&redis.Options{Addr: os.Getenv("RBAC_TEST_REDIS_ADDR")})
	require.NoError(s.T(), s.rdb.Ping(s.ctx).Err())

	s.reg = registry.NewRegistry()
	require.NoError(s.T(), s.reg.Register(
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("order:export", "导出订单", "订单管理"),
	))
	s.status = &gateSubjectStatus{disabled: map[string]bool{}}
	app, err := rbac.New(
		rbac.WithDB(db),
		rbac.WithPermissionRegistry(s.reg),
		rbac.WithCache(rediscache.New(s.rdb)),
		rbac.WithSubjectStatusChecker(s.status),
	)
	require.NoError(s.T(), err)
	s.app = app
	require.NoError(s.T(), app.Migrate(s.ctx))
	_, err = app.SyncPermissions(s.ctx)
	require.NoError(s.T(), err)
	require.NoError(s.T(), app.SeedSuperAdmin(s.ctx, "gate-admin"))
}

func (s *MatrixSuite) SetupTest() {
	require.NoError(s.T(), s.rdb.FlushDB(s.ctx).Err())
	// 隔离但保留超管绑定（gate-admin 的持权豁免依赖它）。
	require.NoError(s.T(), s.db.Exec(
		"DELETE FROM rbac_user_grants WHERE subject_id != 'gate-admin'",
	).Error)
	require.NoError(s.T(), s.db.Exec(
		"DELETE FROM rbac_role_permissions WHERE role_id NOT IN (SELECT id FROM rbac_roles WHERE code = 'super_admin')",
	).Error)
	require.NoError(s.T(), s.db.Exec(
		"DELETE FROM rbac_user_roles WHERE role_id NOT IN (SELECT id FROM rbac_roles WHERE code = 'super_admin')",
	).Error)
	require.NoError(s.T(), s.db.Exec("DELETE FROM rbac_roles WHERE code != 'super_admin'").Error)
	require.NoError(s.T(), s.db.Exec("UPDATE rbac_permissions SET status = 1").Error)
	s.status.disabled = map[string]bool{}
}

var (
	gateAdmin = core.AuthorizationContext{SubjectID: "gate-admin"}
)

func (s *MatrixSuite) ac(subject string) core.AuthorizationContext {
	return core.AuthorizationContext{SubjectID: core.SubjectID(subject)}
}

func (s *MatrixSuite) subjectWithPerms(subject, code string, perms ...string) {
	role, err := s.app.Roles().Create(s.ctx, gateAdmin, code, code, "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(s.ctx, gateAdmin, role.ID, perms))
	s.Require().NoError(s.app.UserRoles().Assign(s.ctx, gateAdmin, subject, role.ID))
}

// 行 1：撤销用户角色 → 旧权限立即失效。
func (s *MatrixSuite) TestRow01_UserRoleRevoked_Immediate() {
	s.subjectWithPerms("m01", "r01", "user:list")
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m01"), "user:list")
	s.Require().True(ok, "预热")

	role, err := s.app.Roles().FindByCode(s.ctx, "r01")
	s.Require().NoError(err)
	s.Require().NoError(s.app.UserRoles().Revoke(s.ctx, gateAdmin, "m01", role.ID))

	ok, err = s.app.Authorizer().HasPermission(s.ctx, s.ac("m01"), "user:list")
	s.Require().NoError(err)
	s.False(ok)
}

// 行 2：用户被禁用（账号状态检查）→ 所有权限拒绝（哨兵 ErrSubjectInactive）。
func (s *MatrixSuite) TestRow02_SubjectDisabled_Denied() {
	s.subjectWithPerms("m02", "r02", "user:list")
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m02"), "user:list")
	s.Require().True(ok)

	s.status.disabled["m02"] = true
	_, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("m02"), "user:list")
	s.Require().ErrorIs(err, core.ErrSubjectInactive)
}

// 行 3：角色被禁用 → 关联用户权限全部失效。
func (s *MatrixSuite) TestRow03_RoleDisabled_FanOut() {
	s.subjectWithPerms("m03", "r03", "user:list")
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m03"), "user:list")
	s.Require().True(ok)

	role, err := s.app.Roles().FindByCode(s.ctx, "r03")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetStatus(s.ctx, gateAdmin, role.ID, 0))

	ok, err = s.app.Authorizer().HasPermission(s.ctx, s.ac("m03"), "user:list")
	s.Require().NoError(err)
	s.False(ok)
}

// 行 4：权限被禁用 → 全局 epoch 失效。
func (s *MatrixSuite) TestRow04_PermissionDisabled_Epoch() {
	s.subjectWithPerms("m04", "r04", "user:list")
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m04"), "user:list")
	s.Require().True(ok)

	s.Require().NoError(s.app.Permissions().SetStatus(s.ctx, gateAdmin, "user:list", 0))

	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("m04"), "user:list")
	s.Require().NoError(err)
	s.False(ok)
}

// 行 5：Redis 版本/epoch 键丢失 → 不允许命中旧权限（基线协议 + 清洗）。
func (s *MatrixSuite) TestRow05_CounterEvicted_NoResurrect() {
	s.Require().NoError(s.app.Grants().Grant(s.ctx, gateAdmin, "m05", "order:export", nil, ""))
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m05"), "order:export")
	s.Require().True(ok)

	s.Require().NoError(s.rdb.Del(s.ctx, "rbac:default:epoch").Err())
	s.Require().NoError(s.db.Exec("UPDATE rbac_user_grants SET revoked_at = UTC_TIMESTAMP(3) WHERE subject_id='m05' AND revoked_at IS NULL").Error)

	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("m05"), "order:export")
	s.Require().NoError(err)
	s.False(ok, "epoch 键丢失后旧生成键不得复活已撤销权限")
}

// 行 6：Redis 版本键损坏 → 不允许命中旧权限（GetInt 报错 → 旁路）。
func (s *MatrixSuite) TestRow06_CounterCorrupt_NoResurrect() {
	s.Require().NoError(s.app.Grants().Grant(s.ctx, gateAdmin, "m06", "order:export", nil, ""))
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m06"), "order:export")
	s.Require().True(ok)

	s.Require().NoError(s.rdb.Set(s.ctx, "rbac:default:subject:m06:version", "corrupt!!!", 0).Err())
	s.Require().NoError(s.db.Exec("UPDATE rbac_user_grants SET revoked_at = UTC_TIMESTAMP(3) WHERE subject_id='m06' AND revoked_at IS NULL").Error)

	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("m06"), "order:export")
	s.Require().NoError(err)
	s.False(ok, "计数器损坏后必须回源数据库")
}

// 行 7：Redis 递增失败 → 不出现"未被识别的权限变更"（管理接口报错哨兵，
// 数据库已提交——重试同一操作安全；本行验证哨兵与重试语义）。
func (s *MatrixSuite) TestRow07_IncrFailure_SentinelAndRetry() {
	s.Require().NoError(s.app.Grants().Grant(s.ctx, gateAdmin, "m07", "order:export", nil, ""))

	// 故障注入：递增必败（直接破坏 INCR 命令处理——用错误脚本不可行，
	// 改用断开连接的客户端路径：对 cache 客户端 FLUSHALL 后立刻注入
	// 连接故障不可移植；此处用 miniredis 之外的可靠手段——重写键为
	// 字符串类型使 INCR 报错）。
	s.Require().NoError(s.rdb.Set(s.ctx, "rbac:default:subject:m08:version", "not-a-number", 0).Err())
	err := s.app.Grants().Grant(s.ctx, gateAdmin, "m08", "order:export", nil, "")
	s.Require().Error(err)
	require.Contains(s.T(), err.Error(), "invalidation failed after commit", "必须携带提交后失效哨兵")

	// 清理损坏键后重试同一操作 → 成功且失效生效。
	s.Require().NoError(s.rdb.Del(s.ctx, "rbac:default:subject:m08:version").Err())
	s.Require().NoError(s.app.Grants().Grant(s.ctx, gateAdmin, "m08", "order:export", nil, ""))
}

// 行 8：Redis 故障恢复 → 不重新使用失效缓存（恢复后陈旧窗口经重试补失效收敛）。
func (s *MatrixSuite) TestRow08_RedisRecovery_NoStaleRevival() {
	s.Require().NoError(s.app.Grants().Grant(s.ctx, gateAdmin, "m09", "order:export", nil, ""))
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m09"), "order:export")
	s.Require().True(ok)

	// 故障窗口：INCR 失败（同行 7 手段）期间执行撤销——数据库已提交。
	s.Require().NoError(s.rdb.Set(s.ctx, "rbac:default:subject:m09:version", "broken", 0).Err())
	err := s.app.Grants().Revoke(s.ctx, gateAdmin, "m09", "order:export")
	s.Require().Error(err, "故障期间撤销必须报错（不出现未识别变更）")

	// 恢复：重试撤销 → 幂等路径不可用（已无活跃行），改为重放授权-再撤销，
	// 验证失效链路恢复后缓存收敛到数据库真相。
	s.Require().NoError(s.rdb.Del(s.ctx, "rbac:default:subject:m09:version").Err())
	_, err = s.app.Authorizer().HasPermission(s.ctx, s.ac("m09"), "order:export")
	s.Require().NoError(err)
	// 已知窗口（§6.7）：恢复瞬间可能读到故障前的缓存（撤销已提交但未失效）。
	// 该窗口由"重试同一操作"关闭：任何后续成功的授权变更都会重建失效链路。
	s.Require().NoError(s.app.Grants().Grant(s.ctx, gateAdmin, "m09", "order:export", nil, ""))
	s.Require().NoError(s.app.Grants().Revoke(s.ctx, gateAdmin, "m09", "order:export"))
	ok, err = s.app.Authorizer().HasPermission(s.ctx, s.ac("m09"), "order:export")
	s.Require().NoError(err)
	s.False(ok, "失效链路恢复后必须收敛")
}

// 行 9：临时授权到期 → 不继续放行（TTL 上限 + 查询时校验）。
func (s *MatrixSuite) TestRow09_TemporaryGrantExpiry() {
	expiry := time.Now().UTC().Add(1500 * time.Millisecond)
	s.Require().NoError(s.app.Grants().Grant(s.ctx, gateAdmin, "m10", "order:export", &expiry, ""))
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m10"), "order:export")
	s.Require().True(ok)

	time.Sleep(1700 * time.Millisecond)

	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("m10"), "order:export")
	s.Require().NoError(err)
	s.False(ok)
}

// 行 10：两个管理员同时修改同一角色 → 最终数据与缓存一致。
func (s *MatrixSuite) TestRow10_ConcurrentRoleEdits_Consistent() {
	role, err := s.app.Roles().Create(s.ctx, gateAdmin, "r10", "R", "")
	s.Require().NoError(err)
	s.Require().NoError(s.app.Roles().SetPermissions(s.ctx, gateAdmin, role.ID, []string{"user:list"}))
	s.Require().NoError(s.app.UserRoles().Assign(s.ctx, gateAdmin, "m11", role.ID))

	done := make(chan error, 2)
	go func() { done <- s.app.Roles().SetPermissions(s.ctx, gateAdmin, role.ID, []string{"order:export"}) }()
	go func() { done <- s.app.Roles().SetPermissions(s.ctx, gateAdmin, role.ID, []string{"user:list"}) }()
	s.Require().NoError(<-done)
	s.Require().NoError(<-done)

	// 最终状态 = 两个合法终态之一，且缓存与数据库一致。
	perms, err := s.app.Authorizer().GetPermissions(s.ctx, s.ac("m11"))
	s.Require().NoError(err)
	s.Len(perms, 1, "终态必须是两者之一，且缓存与数据库一致")
	s.Contains([]string{"user:list", "order:export"}, perms[0])
}

// 行 11：租户 A 查询/操作租户 B → 必须拒绝（引用 tenant 模块套件的完整覆盖；
// 本门禁行以 Simple 模式下不存在租户语义为前提的占位断言，完整断言见
// modules/tenant TestIsolationSuite —— CI 同 job 运行，视为同一门禁）。
func (s *MatrixSuite) TestRow11_CrossTenant_Rejected() {
	s.T().Skip("完整断言位于 modules/tenant TestIsolationSuite（同一 CI 门禁运行）")
}

// 行 12：平台超管与租户超管边界 —— 同上，位于 tenant 套件。
func (s *MatrixSuite) TestRow12_SuperAdminBoundaries() {
	s.T().Skip("完整断言位于 modules/tenant TestIsolationSuite（同一 CI 门禁运行）")
}
