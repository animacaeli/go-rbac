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
	"fmt"
	"os"
	"strconv"
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

// 行 4：权限被禁用 → 全局（跨租户）epoch 失效。
func (s *MatrixSuite) TestRow04_PermissionDisabled_Epoch() {
	s.subjectWithPerms("m04", "r04", "user:list")
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m04"), "user:list")
	s.Require().True(ok)

	s.Require().NoError(s.app.Permissions().SetStatus(s.ctx, gateAdmin, "user:list", 0))

	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("m04"), "user:list")
	s.Require().NoError(err)
	s.False(ok)

	// 权限表是全局定义：失效必须走全局 epoch（单租户 epoch 只能让本域失效）。
	globalEpoch, err := s.rdb.Get(s.ctx, "rbac:!global:epoch").Result()
	s.Require().NoError(err)
	s.NotEqual("0", globalEpoch, "全局 epoch 副本必须被同步")
}

// 行 5：Redis 版本/epoch 键丢失 → 不允许命中旧权限（基线协议 + 清洗）。
func (s *MatrixSuite) TestRow05_CounterEvicted_NoResurrect() {
	s.Require().NoError(s.app.Grants().Grant(s.ctx, gateAdmin, "m05", "order:export", nil, ""))
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m05"), "order:export")
	s.Require().True(ok)

	s.Require().NoError(s.rdb.Del(s.ctx, "rbac:default:epoch").Err())
	s.Require().NoError(s.db.Exec("UPDATE rbac_user_grants SET revoked_at = UTC_TIMESTAMP(3) WHERE subject_id='m05' AND revoked_at IS NULL").Error)
	s.Require().NoError(s.db.Exec(
		"INSERT INTO rbac_counters (k,v,updated_at) VALUES ('default:epoch',1,UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE v=v+1").Error)

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
	s.Require().NoError(s.db.Exec(
		"INSERT INTO rbac_counters (k,v,updated_at) VALUES ('default:subject:m06:version',1,UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE v=v+1").Error)

	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("m06"), "order:export")
	s.Require().NoError(err)
	s.False(ok, "计数器损坏后必须回源数据库")
}

// 行 7（P0-1 精确场景）：副本被淘汰后，同步必须写入权威真值而非从 1 相对递增。
// 场景构造：同一主体两次授权 → 权威=2；副本在两次之间删除。
// 旧 INCR 实现：第二次同步 INCR-from-missing 重建副本为 1（偏差，读者无法察觉）；
// SetIntMax 实现：副本 == 权威真值 == 2。
func (s *MatrixSuite) TestRow07_ReplicaDeleted_SyncWritesTrueValue() {
	// 授权 1：权威 0→1，读路径同步副本。
	s.Require().NoError(s.app.Grants().Grant(s.ctx, gateAdmin, "m07", "order:export", nil, ""))
	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("m07"), "order:export")
	s.Require().NoError(err)
	s.Require().True(ok)

	// 淘汰副本（模拟 allkeys-* 误配 / 竞态删除）。
	s.Require().NoError(s.rdb.Del(s.ctx, "rbac:default:subject:m07:version").Err())

	// 授权 2（重授权：撤销旧行+插新行）：权威 1→2，提交后同步副本。
	s.Require().NoError(s.app.Grants().Grant(s.ctx, gateAdmin, "m07", "order:export", nil, "重授权"))

	// 断言：副本必须等于权威真值（2），不得从 1 相对递增。
	replica, err := s.rdb.Get(s.ctx, "rbac:default:subject:m07:version").Result()
	s.Require().NoError(err, "副本应已由同步重建")
	var dbAfter int64
	s.Require().NoError(s.db.Table("rbac_counters").
		Select("v").Where("k = ?", "default:subject:m07:version").Limit(1).Scan(&dbAfter).Error)
	s.Require().GreaterOrEqual(dbAfter, int64(2), "两次授权后权威应 ≥2")
	s.Require().Equal(fmt.Sprintf("%d", dbAfter), replica,
		"副本必须等于权威真值（P0-1：INCR-from-missing 会重建为 1 造成持久偏差）")
}

// 行 8（P0-2 场景）：恢复与更新同步乱序不回退——功能级验证：
// 全局 epoch 副本淘汰 → 变更（DB bump）→ 读（恢复 SetIntMax 真值）→ 再变更 → 读。
// 副本全程单调前进且鉴权结果始终正确（原子乱序护栏由适配器单测覆盖）。
func (s *MatrixSuite) TestRow08_RecoveryAndSync_NoRegression() {
	s.subjectWithPerms("m09", "r09", "user:list")
	ok, _ := s.app.Authorizer().HasPermission(s.ctx, s.ac("m09"), "user:list")
	s.Require().True(ok)

	s.Require().NoError(s.rdb.Del(s.ctx, "rbac:!global:epoch").Err())
	// 变更 1：禁用权限（DB 全局 epoch 同事务 +1），读路径恢复副本为真值。
	s.Require().NoError(s.app.Permissions().SetStatus(s.ctx, gateAdmin, "user:list", 0))
	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("m09"), "user:list")
	s.Require().NoError(err)
	s.False(ok)
	var e1 string
	e1, err = s.rdb.Get(s.ctx, "rbac:!global:epoch").Result()
	s.Require().NoError(err)

	// 变更 2：重新启用 → epoch 前进；副本必须单调上升且结果正确。
	s.Require().NoError(s.app.Permissions().SetStatus(s.ctx, gateAdmin, "user:list", 1))
	ok, err = s.app.Authorizer().HasPermission(s.ctx, s.ac("m09"), "user:list")
	s.Require().NoError(err)
	s.True(ok)
	var e2 string
	e2, err = s.rdb.Get(s.ctx, "rbac:!global:epoch").Result()
	s.Require().NoError(err)
	s.Require().Greater(metricsCmp(e2, e1), 0, "全局 epoch 副本必须单调前进，不得回退")
}

func metricsCmp(a, b string) int {
	x, _ := strconv.ParseInt(a, 10, 64)
	y, _ := strconv.ParseInt(b, 10, 64)
	switch {
	case x > y:
		return 1
	case x < y:
		return -1
	default:
		return 0
	}
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

// P1-1 专项（外部审核第三轮）：多实例并发恢复。
// 两个服务实例共享同一 MySQL/Redis；计数器副本被淘汰后，两实例并发恢复
// 必须从 DB 权威值收敛（SetInt 幂等），且不产生陈旧命中。
func (s *MatrixSuite) TestRow13_MultiInstanceConcurrentRecovery() {
	ctx := context.Background()
	s.subjectWithPerms("m13", "r13", "user:list")
	m1 := s.app
	// 第二实例：同一 DB + 同一 Redis 的独立 App。
	m2, err := rbac.New(
		rbac.WithDB(s.db),
		rbac.WithPermissionRegistry(s.reg),
		rbac.WithCache(rediscache.New(s.rdb)),
	)
	s.Require().NoError(err)

	ok1, err := m1.Authorizer().HasPermission(ctx, s.ac("m13"), "user:list")
	s.Require().NoError(err)
	s.True(ok1)

	// 淘汰计数器副本 + 数据库撤销角色（同事务语义：变更与权威版本递增一并落库）。
	s.Require().NoError(s.rdb.Del(ctx, "rbac:default:subject:m13:version").Err())
	s.Require().NoError(s.db.Exec("DELETE FROM rbac_user_roles WHERE subject_id='m13'").Error)
	s.Require().NoError(s.db.Exec(
		"INSERT INTO rbac_counters (k,v,updated_at) VALUES ('default:subject:m13:version',1,UTC_TIMESTAMP(3)) " +
			"ON DUPLICATE KEY UPDATE v=v+1, updated_at=UTC_TIMESTAMP(3)").Error)

	// 两实例并发读取：均以 DB 权威值恢复，均得数据库真相。
	done := make(chan bool, 2)
	for _, app := range []*rbac.App{m1, m2} {
		go func(a *rbac.App) {
			got, err := a.Authorizer().HasPermission(ctx, s.ac("m13"), "user:list")
			done <- err == nil && !got
		}(app)
	}
	s.True(<-done, "实例 1 必须读到数据库真相（撤销生效）")
	s.True(<-done, "实例 2 必须读到数据库真相（撤销生效）")

	// 恢复后缓存收敛到权威生成键。
	diag, err := m1.CacheDiagnostics(ctx, s.ac("m13"))
	s.Require().NoError(err)
	s.True(diag.EpochExists, "副本已从 DB 回填")
}

// 行 14：subject_id / tenant_id 大小写规范化——库表排序规则大小写不敏感，
// 缓存/计数器键必须同样规范化，否则"只同步了一种拼写"会让另一种拼写的
// 旧缓存存活到 TTL（陈旧权限放行）。
func (s *MatrixSuite) TestRow14_SubjectCaseCanonicalized() {
	s.subjectWithPerms("CaseUser", "r14", "user:list")
	ok, err := s.app.Authorizer().HasPermission(s.ctx, s.ac("CaseUser"), "user:list")
	s.Require().NoError(err)
	s.Require().True(ok, "预热（大写拼写）")

	role, err := s.app.Roles().FindByCode(s.ctx, "r14")
	s.Require().NoError(err)
	// 用小写拼写撤销：DB 命中同一行，缓存/计数器域也必须命中同一份。
	s.Require().NoError(s.app.UserRoles().Revoke(s.ctx, gateAdmin, "caseuser", role.ID))

	ok, err = s.app.Authorizer().HasPermission(s.ctx, s.ac("CaseUser"), "user:list")
	s.Require().NoError(err)
	s.False(ok, "大小写不同的同一 subject 必须共享失效结果")
}
