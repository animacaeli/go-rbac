package core_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/animacaeli/go-rbac/cache"

	"github.com/animacaeli/go-rbac/core"
	cachemocks "github.com/animacaeli/go-rbac/test/mocks/cache"
	coremocks "github.com/animacaeli/go-rbac/test/mocks/core"
	repositorymocks "github.com/animacaeli/go-rbac/test/mocks/repository"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type AuthorizationServiceSuite struct {
	suite.Suite
	ctx       context.Context
	authzRepo *repositorymocks.MockAuthorizationRepo
	counters  *repositorymocks.MockCountersRepo
	cch       *cachemocks.MockPermissionCache
	checker   *coremocks.MockSubjectStatusChecker
	sut       *core.AuthorizationService
}

func (s *AuthorizationServiceSuite) SetupTest() {
	s.ctx = context.Background()
	s.authzRepo = repositorymocks.NewMockAuthorizationRepo(s.T())
	s.cch = cachemocks.NewMockPermissionCache(s.T())
	s.checker = coremocks.NewMockSubjectStatusChecker(s.T())
	s.counters = repositorymocks.NewMockCountersRepo(s.T())
	s.counters.On("Get", mock.Anything, mock.Anything).Return(int64(0), nil).Maybe()
	s.cch.On("SetIntMax", mock.Anything, mock.Anything, mock.AnythingOfType("int64")).Return(nil).Maybe()
	s.sut = core.NewAuthorizationService(s.authzRepo, s.counters, s.cch, nil, core.NoopMetrics{}, 5*time.Minute)
}

func TestAuthorizationServiceSuite(t *testing.T) { suite.Run(t, new(AuthorizationServiceSuite)) }

var (
	subject1 = core.AuthorizationContext{SubjectID: "10001"}
	subject2 = core.AuthorizationContext{SubjectID: "10002"}
)

// generation 计算生成键（与实现保持一致：epoch<<32 | version）。
func generation(epoch, version int64) int64 { return epoch<<32 | version }

func permKey(subject string, gen int64) string {
	return "rbac:default:subject:" + subject + ":perm:v" + strconv.FormatInt(gen, 10)
}

func versionKey(subject string) string {
	return "rbac:default:subject:" + subject + ":version"
}

// expectColdRead 配置一次完整冷读：生成键 (epoch, version)，缓存未命中，
// 数据库聚合 rolePerms ∪ grantPerms，写回。
func (s *AuthorizationServiceSuite) expectColdRead(subject core.AuthorizationContext, epoch, version int64, rolePerms, grantPerms []string, nearest *time.Time) {
	sid := subject.SubjectID.String()
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, sid).Return(false, nil)
	// DB 权威计数器兜底（读路径仅在副本缺失/损坏时触达）。
	s.counters.On("Get", mock.Anything, mock.Anything).Return(int64(0), nil).Maybe()
	s.cch.On("SetIntMax", mock.Anything, mock.Anything, mock.AnythingOfType("int64")).Return(nil).Maybe()
	// 快路径 + flight 内二次探测 + 写回前复核：GetInt 可能被多次调用。
	s.cch.On("GetInt", mock.Anything, "rbac:default:epoch").Return(epoch, true, nil)
	s.cch.On("GetInt", mock.Anything, versionKey(sid)).Return(version, true, nil)
	s.cch.On("Get", mock.Anything, permKey(sid, generation(epoch, version))).Return(nil, false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, sid).Return(rolePerms, nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(grantPerms, nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nearest, nil)
	s.cch.On("Set", mock.Anything, permKey(sid, generation(epoch, version)), mock.Anything, mock.Anything).Return(nil).Maybe()
}

func (s *AuthorizationServiceSuite) TestGetPermissions_MultiRoleUnionWithGrants() {
	// Arrange
	s.expectColdRead(subject1, 0, 0,
		[]string{"user:list", "order:list"},
		[]string{"order:export", "user:list"},
		nil,
	)

	// Act
	perms, err := s.sut.GetPermissions(s.ctx, subject1)

	// Assert
	s.Require().NoError(err)
	s.Equal([]string{"order:export", "order:list", "user:list"}, perms)
}

func (s *AuthorizationServiceSuite) TestHasPermission_LiteralMatch() {
	tests := []struct {
		name       string
		permission string
		want       bool
	}{
		{"held", "user:list", true},
		{"not_held", "user:delete", false},
		{"prefix_not_wildcard", "user", false},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			// Arrange
			s.expectColdRead(subject1, 0, 0, []string{"user:list"}, nil, nil)

			// Act
			ok, err := s.sut.HasPermission(s.ctx, subject1, tt.permission)

			// Assert
			s.Require().NoError(err)
			s.Equal(tt.want, ok)
		})
	}
}

func (s *AuthorizationServiceSuite) TestHasAnyHasAll_Semantics() {
	// Arrange
	s.expectColdRead(subject1, 0, 0, []string{"user:list", "order:list"}, nil, nil)

	// Act + Assert
	any, err := s.sut.HasAnyPermission(s.ctx, subject1, "user:delete", "order:list")
	s.Require().NoError(err)
	s.True(any)

	all, err := s.sut.HasAllPermissions(s.ctx, subject1, "user:list", "order:list")
	s.Require().NoError(err)
	s.True(all)

	all, err = s.sut.HasAllPermissions(s.ctx, subject1, "user:list", "order:export")
	s.Require().NoError(err)
	s.False(all)
}

func (s *AuthorizationServiceSuite) TestHasEmptyPermissionCodes_FailClosed() {
	// Act
	_, errAny := s.sut.HasAnyPermission(s.ctx, subject1)
	_, errAll := s.sut.HasAllPermissions(s.ctx, subject1)
	_, errOne := s.sut.HasPermission(s.ctx, subject1, "")

	// Assert
	s.ErrorIs(errAny, core.ErrNoPermissionDeclared)
	s.ErrorIs(errAll, core.ErrNoPermissionDeclared)
	s.ErrorIs(errOne, core.ErrNoPermissionDeclared)
}

func (s *AuthorizationServiceSuite) TestSuperAdmin_HasPermissionAlwaysTrue() {
	// Arrange：超管判定在回源路径内完成，结果以哨兵码缓存。
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, subject1.SubjectID.String()).
		Return(true, nil)
	s.cch.On("GetInt", mock.Anything, "rbac:default:epoch").Return(int64(0), true, nil)
	s.cch.On("GetInt", mock.Anything, versionKey("10001")).Return(int64(0), true, nil)
	s.cch.On("Get", mock.Anything, mock.Anything).Return(nil, false, nil)
	s.cch.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	// Act
	ok, err := s.sut.HasPermission(s.ctx, subject1, "anything:whatever")
	perms, permErr := s.sut.GetPermissions(s.ctx, subject1)
	isSuper, superErr := s.sut.IsSuperAdministrator(s.ctx, subject1)

	// Assert
	s.Require().NoError(err)
	s.True(ok)
	s.Require().NoError(permErr)
	s.Empty(perms, "§4.3：超管 GetPermissions 返回空集合，不引入通配符语义")
	s.Require().NoError(superErr)
	s.True(isSuper)
}

func (s *AuthorizationServiceSuite) TestSubjectInactive_DeniedWithSentinel() {
	// Arrange
	sut := core.NewAuthorizationService(s.authzRepo, s.counters, s.cch, s.checker, core.NoopMetrics{}, time.Minute)
	s.checker.On("IsSubjectActive", mock.Anything, subject1.SubjectID).
		Return(false, nil)

	// Act
	ok, err := sut.HasPermission(s.ctx, subject1, "user:list")

	// Assert
	s.Require().ErrorIs(err, core.ErrSubjectInactive)
	s.False(ok)
}

func (s *AuthorizationServiceSuite) TestSubjectStatusCheckError_FailClosed() {
	// Arrange
	sut := core.NewAuthorizationService(s.authzRepo, s.counters, s.cch, s.checker, core.NoopMetrics{}, time.Minute)
	s.checker.On("IsSubjectActive", mock.Anything, subject1.SubjectID).
		Return(false, errors.New("user service down"))

	// Act
	ok, err := sut.HasPermission(s.ctx, subject1, "user:list")

	// Assert
	s.Require().Error(err)
	s.False(ok, "查询失败不得视为授权成功")
}

func (s *AuthorizationServiceSuite) TestInvalidContext_FailClosed() {
	tests := []struct {
		name string
		ac   core.AuthorizationContext
		want error
	}{
		{"empty_subject", core.AuthorizationContext{}, core.ErrInvalidSubjectID},
		{"subject_too_long", core.AuthorizationContext{SubjectID: core.SubjectID(makeLongString(129))}, core.ErrInvalidSubjectID},
		{"tenant_not_empty", core.AuthorizationContext{SubjectID: "10001", TenantID: "t1"}, core.ErrTenantNotSupported},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			// Act
			ok, err := s.sut.HasPermission(s.ctx, tt.ac, "user:list")

			// Assert
			s.Require().ErrorIs(err, tt.want)
			s.False(ok)
		})
	}
}

func (s *AuthorizationServiceSuite) TestRepoError_FailClosed() {
	// Arrange：回源路径内超管判定失败 → fail closed。
	s.cch.On("GetInt", mock.Anything, "rbac:default:epoch").Return(int64(0), true, nil)
	s.cch.On("GetInt", mock.Anything, versionKey("10001")).Return(int64(0), true, nil)
	s.cch.On("Get", mock.Anything, mock.Anything).Return(nil, false, nil)
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, subject1.SubjectID.String()).
		Return(false, errors.New("db down"))

	// Act
	ok, err := s.sut.HasPermission(s.ctx, subject1, "user:list")

	// Assert
	s.Require().Error(err)
	s.False(ok)
}

// §6.2：命中路径不触达数据库。
func (s *AuthorizationServiceSuite) TestCacheHit_RepoNotQueried() {
	// Arrange：生成键 epoch=3, version=7。
	gen := generation(3, 7)
	s.cch.On("GetInt", mock.Anything, "rbac:default:epoch").Return(int64(3), true, nil)
	s.cch.On("GetInt", mock.Anything, versionKey("10001")).Return(int64(7), true, nil)
	s.cch.On("Get", mock.Anything, permKey("10001", gen)).Return([]string{"user:list"}, true, nil)
	// 仓储无任何期望：命中路径（含超管判定）零数据库查询（§9.4）。

	// Act
	ok, err := s.sut.HasPermission(s.ctx, subject1, "user:list")

	// Assert
	s.Require().NoError(err)
	s.True(ok)
}

// §6.5：写回 TTL 不超过最近临时授权到期时间。
func (s *AuthorizationServiceSuite) TestCacheTTL_CappedByNearestGrantExpiry() {
	// Arrange
	expiry := time.Now().UTC().Add(time.Minute)
	s.expectColdRead(subject2, 0, 0, nil, []string{"order:export"}, &expiry)
	s.cch.On("Set", mock.Anything, permKey("10002", 0), mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			ttl := args.Get(3).(time.Duration)
			s.Greater(ttl, 50*time.Second)
			s.LessOrEqual(ttl, time.Minute)
		}).
		Return(nil)

	// Act
	perms, err := s.sut.GetPermissions(s.ctx, subject2)

	// Assert
	s.Require().NoError(err)
	s.Equal([]string{"order:export"}, perms)
}

// §6.3：授权变更失效 = 副本同步（读权威真值 + SetIntMax 单调写回）。
// 本地 mock（泛型桩会先匹配遮蔽精确失败桩）。
func (s *AuthorizationServiceSuite) TestSync_Operations() {
	cch := cachemocks.NewMockPermissionCache(s.T())
	counters := repositorymocks.NewMockCountersRepo(s.T())
	sut := core.NewAuthorizationService(s.authzRepo, counters, cch, nil, core.NoopMetrics{}, time.Minute)

	// 10001 被单测同步 + 批量同步各调用一次。
	counters.On("Get", mock.Anything, "default:subject:10001:version").Return(int64(1), nil).Twice()
	cch.On("SetIntMax", mock.Anything, versionKey("10001"), int64(1)).Return(nil).Twice()
	counters.On("Get", mock.Anything, "default:epoch").Return(int64(1), nil).Once()
	cch.On("SetIntMax", mock.Anything, "rbac:default:epoch", int64(1)).Return(nil).Once()
	// 10002 的权威读取失败 → 删副本 + 批量同步整体报错（§6.6）。
	counters.On("Get", mock.Anything, "default:subject:10002:version").
		Return(int64(0), errors.New("db down")).Once()
	cch.On("Delete", mock.Anything, versionKey("10002")).Return(nil).Once()

	s.Require().NoError(sut.SyncSubjectVersion(s.ctx, subject1.SubjectID))
	s.Require().NoError(sut.SyncEpoch(s.ctx))
	s.Require().Error(sut.SyncSubjectVersions(s.ctx, []string{"10001", "10002"}))
}

// §6.8：singleflight 击穿防护——同主体并发未命中只触发一次数据库聚合。
func (s *AuthorizationServiceSuite) TestSingleflight_ConcurrentMisses_SingleDBAggregate() {
	// Arrange
	sid := "10001"
	s.cch.On("GetInt", mock.Anything, "rbac:default:epoch").Return(int64(0), true, nil)
	s.cch.On("GetInt", mock.Anything, versionKey(sid)).Return(int64(0), true, nil)
	s.cch.On("Get", mock.Anything, mock.Anything).Return(nil, false, nil)
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, sid).Return(false, nil)
	// 聚合耗时 100ms：并发请求在此窗口内到达，singleflight 合并为一次回源。
	// .Once()：多余聚合会使 mock panic —— 断言即"恰好一次"。
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, sid).
		Run(func(mock.Arguments) { time.Sleep(100 * time.Millisecond) }).
		Return([]string{"user:list"}, nil).Once()
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, sid, mock.AnythingOfType("time.Time")).
		Return(nil, nil).Once()
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, sid, mock.AnythingOfType("time.Time")).
		Return(nil, nil).Once()
	s.cch.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	const n = 20
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]bool, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = s.sut.HasPermission(s.ctx, subject1, "user:list")
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < n; i++ {
		s.Require().NoError(errs[i])
		s.True(results[i])
	}
}

func makeLongString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}

// §6.4 主从延迟边界（文档化测试）：若回填报源读到的是延迟从库的旧数据，
// 且期间无新的版本递增，旧数据会被写进当前生成键——这正是"缓存回填路径
// 必须读主库"规则存在的原因（v1 以单一主库句柄 + 文档声明兜底，§9.2）。
// 本测试固定该边界行为：规则被破坏时的失效模式可观测、可解释。
func (s *AuthorizationServiceSuite) TestStaleReplicaRead_DocumentedLimitation() {
	// Arrange：聚合#1（主库）返回真实数据；聚合#2（模拟延迟从库）返回旧数据。
	// 缓存 Get 恒 miss → 第二次读取触发第二次聚合与写回。
	sid := "10001"
	s.cch.On("GetInt", mock.Anything, "rbac:default:epoch").Return(int64(0), true, nil)
	s.cch.On("GetInt", mock.Anything, versionKey(sid)).Return(int64(0), true, nil)
	s.cch.On("Get", mock.Anything, mock.Anything).Return(nil, false, nil)
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, sid).Return(false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, sid).
		Return([]string{"user:list"}, nil).Once() // #1 主库：真实
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, sid).
		Return(nil, nil).Once() // #2 从库：过期
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nil, nil).Twice()
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nil, nil).Twice()
	var cached []string
	s.cch.On("Set", mock.Anything, permKey(sid, 0), mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { cached = args.Get(2).([]string) }).
		Return(nil).Twice()

	// Act：两次读取（第二次命中被污染的缓存）。
	first, err := s.sut.GetPermissions(s.ctx, subject1)
	s.Require().NoError(err)
	second, err := s.sut.GetPermissions(s.ctx, subject1)
	s.Require().NoError(err)

	// Assert：第二次读到的是"从库旧数据"——§6.4 已知边界。
	// 部署约束（README/设计文档）：回填路径读主库即可避免本场景。
	s.Equal([]string{"user:list"}, first)
	s.Empty(second)
	s.Empty(cached, "被污染写回的内容为旧集合（该键在 TTL 内持续返回旧数据）")
}

// P0 回归（外部审核第三轮，DB 权威版）：计数器缺失/损坏 → 从数据库回填
// 权威值（而非重置归零），生成键取真实版本——历史陈旧条目天然不可达。
// （本地 mock 组合，避开 SetupTest 泛型桩的先注册匹配。）
func (s *AuthorizationServiceSuite) TestCounterMissing_RecoversFromDB() {
	cch := cachemocks.NewMockPermissionCache(s.T())
	counters := repositorymocks.NewMockCountersRepo(s.T())
	sut := core.NewAuthorizationService(s.authzRepo, counters, cch, nil, core.NoopMetrics{}, time.Minute)
	sid := "10001"

	cch.On("GetInt", mock.Anything, "rbac:default:epoch").Return(int64(0), false, nil)
	cch.On("GetInt", mock.Anything, versionKey(sid)).Return(int64(0), false, nil)
	counters.On("Get", mock.Anything, "default:epoch").Return(int64(2), nil).Twice()
	counters.On("Get", mock.Anything, "default:subject:10001:version").Return(int64(5), nil).Twice()
	cch.On("SetIntMax", mock.Anything, "rbac:default:epoch", int64(2)).Return(nil).Maybe()
	cch.On("SetIntMax", mock.Anything, versionKey(sid), int64(5)).Return(nil).Maybe()
	cch.On("Get", mock.Anything, mock.Anything).Return(nil, false, nil)
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, sid).Return(false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, sid).Return([]string{"user:list"}, nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nil, nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nil, nil)
	cch.On("Set", mock.Anything, permKey(sid, generation(2, 5)), mock.Anything, mock.Anything).Return(nil).Maybe()

	perms, err := sut.GetPermissions(s.ctx, subject1)
	s.Require().NoError(err)
	s.Equal([]string{"user:list"}, perms)
}

// 计数器损坏：同样 DB 回退（值损坏路径先删再回填）。
func (s *AuthorizationServiceSuite) TestCounterCorrupt_RecoversFromDB() {
	cch := cachemocks.NewMockPermissionCache(s.T())
	counters := repositorymocks.NewMockCountersRepo(s.T())
	sut := core.NewAuthorizationService(s.authzRepo, counters, cch, nil, core.NoopMetrics{}, time.Minute)
	sid := "10001"

	cch.On("GetInt", mock.Anything, "rbac:default:epoch").
		Return(int64(0), false, errors.New("rbac/cache/redis: corrupt integer"))
	cch.On("GetInt", mock.Anything, versionKey(sid)).
		Return(int64(0), false, errors.New("rbac/cache/redis: corrupt integer"))
	counters.On("Get", mock.Anything, mock.Anything).Return(int64(0), nil)
	cch.On("Delete", mock.Anything, mock.Anything).Return(nil).Maybe()
	cch.On("SetIntMax", mock.Anything, mock.Anything, mock.AnythingOfType("int64")).Return(nil).Maybe()
	cch.On("Get", mock.Anything, mock.Anything).Return(nil, false, nil)
	cch.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, sid).Return(false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, sid).Return([]string{"user:list"}, nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nil, nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nil, nil)

	perms, err := sut.GetPermissions(s.ctx, subject1)
	s.Require().NoError(err)
	s.Equal([]string{"user:list"}, perms)
}

// 缓存整体故障 + DB 计数器也不可用：直接回源授权数据，不读缓存。
func (s *AuthorizationServiceSuite) TestCacheError_FallsBackToDBWithoutWriteBack() {
	cch := cachemocks.NewMockPermissionCache(s.T())
	counters := repositorymocks.NewMockCountersRepo(s.T())
	sut := core.NewAuthorizationService(s.authzRepo, counters, cch, nil, core.NoopMetrics{}, time.Minute)
	sid := "10001"

	cch.On("GetInt", mock.Anything, "rbac:default:epoch").
		Return(int64(0), false, errors.New("redis down"))
	cch.On("GetInt", mock.Anything, versionKey(sid)).
		Return(int64(0), false, errors.New("redis down"))
	counters.On("Get", mock.Anything, mock.Anything).Return(int64(0), errors.New("db also down"))
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, sid).Return(false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, sid).Return([]string{"user:list"}, nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nil, nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nil, nil)

	ok, err := sut.HasPermission(s.ctx, subject1, "user:list")
	s.Require().NoError(err)
	s.True(ok)
}

// 写前复核（DB 权威版）：外层权威生成键 (0,0) → flight 内副本已变 (0,1)
// → 复核不一致 → 丢弃重走；第二轮稳定。
func (s *AuthorizationServiceSuite) TestWriteBackVerify_GenerationChanged_Retry() {
	cch := cachemocks.NewMockPermissionCache(s.T())
	counters := repositorymocks.NewMockCountersRepo(s.T())
	sut := core.NewAuthorizationService(s.authzRepo, counters, cch, nil, core.NoopMetrics{}, time.Minute)
	sid := "10001"
	vk := versionKey(sid)

	cch.On("GetInt", mock.Anything, "rbac:default:epoch").Return(int64(0), true, nil)
	// 首读 version=0；其后（并发授权变更后）恒为 1。
	cch.On("GetInt", mock.Anything, vk).Return(int64(0), true, nil).Once()
	cch.On("GetInt", mock.Anything, vk).Return(int64(1), true, nil)
	cch.On("Get", mock.Anything, mock.Anything).Return(nil, false, nil)
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, sid).Return(false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, sid).Return([]string{"user:list"}, nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nil, nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, sid, mock.AnythingOfType("time.Time")).Return(nil, nil)
	// 仅允许写入复核通过后的 v(0,1)；写入 v(0,0)（过期生成键）即 panic。
	cch.On("Set", mock.Anything, permKey(sid, generation(0, 1)), mock.Anything, mock.Anything).Return(nil).Maybe()

	ok, err := sut.HasPermission(s.ctx, subject1, "user:list")
	s.Require().NoError(err)
	s.True(ok)
}

// SyncSubjectVersion/SyncEpoch（DB 权威版）：读权威真值 + SetIntMax 单调写回。
func (s *AuthorizationServiceSuite) TestSync_ReplicaSync() {
	cch := cachemocks.NewMockPermissionCache(s.T())
	counters := repositorymocks.NewMockCountersRepo(s.T())
	sut := core.NewAuthorizationService(s.authzRepo, counters, cch, nil, core.NoopMetrics{}, time.Minute)

	counters.On("Get", mock.Anything, "default:subject:10001:version").Return(int64(7), nil).Once()
	cch.On("SetIntMax", mock.Anything, versionKey("10001"), int64(7)).Return(nil).Once()
	s.Require().NoError(sut.SyncSubjectVersion(s.ctx, subject1.SubjectID))

	counters.On("Get", mock.Anything, "default:epoch").Return(int64(3), nil).Once()
	cch.On("SetIntMax", mock.Anything, "rbac:default:epoch", int64(3)).Return(nil).Once()
	s.Require().NoError(sut.SyncEpoch(s.ctx))
}

// P0-1 回归：副本同步失败（读权威或写回任一失败）→ 删副本 → 返回错误。
// 删除副本后，后续读取回退 DB 权威值，不会看到"在场但偏差"的计数器。
func (s *AuthorizationServiceSuite) TestSync_FailureDeletesReplica() {
	cch := cachemocks.NewMockPermissionCache(s.T())
	counters := repositorymocks.NewMockCountersRepo(s.T())
	sut := core.NewAuthorizationService(s.authzRepo, counters, cch, nil, core.NoopMetrics{}, time.Minute)

	// 写回失败路径。
	counters.On("Get", mock.Anything, "default:subject:10001:version").Return(int64(7), nil).Once()
	cch.On("SetIntMax", mock.Anything, versionKey("10001"), int64(7)).
		Return(errors.New("redis down")).Once()
	cch.On("Delete", mock.Anything, versionKey("10001")).Return(nil).Once()
	s.Require().Error(sut.SyncSubjectVersion(s.ctx, subject1.SubjectID))

	// 读权威失败路径（epoch）。
	counters.On("Get", mock.Anything, "default:epoch").
		Return(int64(0), errors.New("db down")).Once()
	cch.On("Delete", mock.Anything, "rbac:default:epoch").Return(nil).Once()
	s.Require().Error(sut.SyncEpoch(s.ctx))
}

// 第六轮审核：Simple 模式（NoopCache）跳过计数器协议——不得产生权威计数器查询
// （否则每次鉴权 +4 次 DB 查询，违反 Simple 模式的性能契约）。
func (s *AuthorizationServiceSuite) TestSimpleMode_SkipsCounterProtocol() {
	// NoopCache + counters mock 未注册任何期望：任何 counters.Get 即 panic。
	sut := core.NewAuthorizationService(s.authzRepo, s.counters, cache.NoopCache{}, nil, core.NoopMetrics{}, time.Minute)
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, "10001").Return(false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, "10001").Return([]string{"user:list"}, nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, "10001", mock.AnythingOfType("time.Time")).Return(nil, nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, "10001", mock.AnythingOfType("time.Time")).Return(nil, nil)

	ok, err := sut.HasPermission(s.ctx, subject1, "user:list")
	s.Require().NoError(err)
	s.True(ok)
}
