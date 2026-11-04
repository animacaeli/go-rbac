package core_test

import (
	"context"
	"errors"
	"testing"
	"time"

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
	cch       *cachemocks.MockPermissionCache
	checker   *coremocks.MockSubjectStatusChecker
	sut       *core.AuthorizationService
}

func (s *AuthorizationServiceSuite) SetupTest() {
	s.ctx = context.Background()
	s.authzRepo = repositorymocks.NewMockAuthorizationRepo(s.T())
	s.cch = cachemocks.NewMockPermissionCache(s.T())
	s.checker = coremocks.NewMockSubjectStatusChecker(s.T())
	s.sut = core.NewAuthorizationService(s.authzRepo, s.cch, nil, core.NoopMetrics{}, 5*time.Minute)
}

func TestAuthorizationServiceSuite(t *testing.T) { suite.Run(t, new(AuthorizationServiceSuite)) }

var (
	operator1 = core.AuthorizationContext{SubjectID: "10001"}
	operator2 = core.AuthorizationContext{SubjectID: "10002"}
)

// expectNormalSubject 配置一个非超管主体：缓存未命中，从数据库聚合两条来源。
func (s *AuthorizationServiceSuite) expectNormalSubject(subject core.AuthorizationContext, rolePerms, grantPerms []string) {
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, subject.SubjectID.String()).
		Return(false, nil)
	s.cch.On("Get", mock.Anything, mock.Anything).Return(nil, false, nil).Maybe()
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, subject.SubjectID.String()).
		Return(rolePerms, nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, subject.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return(grantPerms, nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, subject.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return(nil, nil)
	s.cch.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Maybe()
}

func (s *AuthorizationServiceSuite) TestGetPermissions_MultiRoleUnionWithGrants() {
	// Arrange
	s.expectNormalSubject(operator1,
		[]string{"user:list", "order:list"},   // 角色权限（跨角色并集）
		[]string{"order:export", "user:list"}, // 额外授权（与角色重叠一项）
	)

	// Act
	perms, err := s.sut.GetPermissions(s.ctx, operator1)

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
			s.expectNormalSubject(operator1, []string{"user:list"}, nil)

			// Act
			ok, err := s.sut.HasPermission(s.ctx, operator1, tt.permission)

			// Assert
			s.Require().NoError(err)
			s.Equal(tt.want, ok)
		})
	}
}

func (s *AuthorizationServiceSuite) TestHasAnyHasAll_Semantics() {
	// Arrange
	s.expectNormalSubject(operator1, []string{"user:list", "order:list"}, nil)

	// Act + Assert
	any, err := s.sut.HasAnyPermission(s.ctx, operator1, "user:delete", "order:list")
	s.Require().NoError(err)
	s.True(any)

	all, err := s.sut.HasAllPermissions(s.ctx, operator1, "user:list", "order:list")
	s.Require().NoError(err)
	s.True(all)

	all, err = s.sut.HasAllPermissions(s.ctx, operator1, "user:list", "order:export")
	s.Require().NoError(err)
	s.False(all)
}

func (s *AuthorizationServiceSuite) TestHasEmptyPermissionCodes_FailClosed() {
	// Arrange — 不设置任何仓储期望：不应触达仓储。

	// Act
	_, errAny := s.sut.HasAnyPermission(s.ctx, operator1)
	_, errAll := s.sut.HasAllPermissions(s.ctx, operator1)
	_, errOne := s.sut.HasPermission(s.ctx, operator1, "")

	// Assert
	s.ErrorIs(errAny, core.ErrNoPermissionDeclared)
	s.ErrorIs(errAll, core.ErrNoPermissionDeclared)
	s.ErrorIs(errOne, core.ErrNoPermissionDeclared)
}

func (s *AuthorizationServiceSuite) TestSuperAdmin_HasPermissionAlwaysTrue() {
	// Arrange
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, operator1.SubjectID.String()).
		Return(true, nil)

	// Act
	ok, err := s.sut.HasPermission(s.ctx, operator1, "anything:whatever")
	perms, permErr := s.sut.GetPermissions(s.ctx, operator1)
	isSuper, superErr := s.sut.IsSuperAdministrator(s.ctx, operator1)

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
	sut := core.NewAuthorizationService(s.authzRepo, s.cch, s.checker, core.NoopMetrics{}, time.Minute)
	s.checker.On("IsSubjectActive", mock.Anything, operator1.SubjectID).
		Return(false, nil)

	// Act
	ok, err := sut.HasPermission(s.ctx, operator1, "user:list")

	// Assert
	s.Require().ErrorIs(err, core.ErrSubjectInactive)
	s.False(ok)
}

func (s *AuthorizationServiceSuite) TestSubjectStatusCheckError_FailClosed() {
	// Arrange
	sut := core.NewAuthorizationService(s.authzRepo, s.cch, s.checker, core.NoopMetrics{}, time.Minute)
	s.checker.On("IsSubjectActive", mock.Anything, operator1.SubjectID).
		Return(false, errors.New("user service down"))

	// Act
	ok, err := sut.HasPermission(s.ctx, operator1, "user:list")

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
	// Arrange
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, operator1.SubjectID.String()).
		Return(false, errors.New("db down"))

	// Act
	ok, err := s.sut.HasPermission(s.ctx, operator1, "user:list")

	// Assert
	s.Require().Error(err)
	s.False(ok)
}

func (s *AuthorizationServiceSuite) TestCacheHit_RepoNotQueried() {
	// Arrange
	key := "rbac:default:subject:10001:perm"
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, operator1.SubjectID.String()).
		Return(false, nil)
	s.cch.On("Get", mock.Anything, key).Return([]string{"user:list"}, true, nil)
	// Effective* / Set 均未设置期望：命中路径不得回源。

	// Act
	ok, err := s.sut.HasPermission(s.ctx, operator1, "user:list")

	// Assert
	s.Require().NoError(err)
	s.True(ok)
}

func (s *AuthorizationServiceSuite) TestCacheError_FallsBackToDB() {
	// Arrange
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, operator1.SubjectID.String()).
		Return(false, nil)
	s.cch.On("Get", mock.Anything, mock.Anything).Return(nil, false, errors.New("redis down"))
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, operator1.SubjectID.String()).
		Return([]string{"user:list"}, nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, operator1.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return(nil, nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, operator1.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return(nil, nil)
	s.cch.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	// Act
	ok, err := s.sut.HasPermission(s.ctx, operator1, "user:list")

	// Assert：§6.6 Redis 故障时鉴权回源数据库。
	s.Require().NoError(err)
	s.True(ok)
}

func (s *AuthorizationServiceSuite) TestCacheTTL_CappedByNearestGrantExpiry() {
	// Arrange
	sut := core.NewAuthorizationService(s.authzRepo, s.cch, nil, core.NoopMetrics{}, 5*time.Minute)
	key := "rbac:default:subject:10002:perm"
	expiry := time.Now().UTC().Add(time.Minute)
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, operator2.SubjectID.String()).
		Return(false, nil)
	s.cch.On("Get", mock.Anything, key).Return(nil, false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, operator2.SubjectID.String()).
		Return(nil, nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, operator2.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return([]string{"order:export"}, nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, operator2.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return(&expiry, nil)
	// §6.5：TTL 不得超过最近到期时间 → 期望 Set 的 ttl ≈ 1 分钟。
	s.cch.On("Set", mock.Anything, key, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			ttl := args.Get(3).(time.Duration)
			s.Greater(ttl, 50*time.Second)
			s.LessOrEqual(ttl, time.Minute)
		}).
		Return(nil)

	// Act
	perms, err := sut.GetPermissions(s.ctx, operator2)

	// Assert
	s.Require().NoError(err)
	s.Equal([]string{"order:export"}, perms)
}

func (s *AuthorizationServiceSuite) TestInvalidateSubject_DeletesCacheKey() {
	// Arrange
	key := "rbac:default:subject:10001:perm"
	s.cch.On("Delete", mock.Anything, key).Return(nil)

	// Act
	err := s.sut.InvalidateSubject(s.ctx, operator1.SubjectID)

	// Assert
	s.Require().NoError(err)
}

func makeLongString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}
