package core_test

import (
	"time"

	"github.com/alicebob/miniredis/v2"
	rediscache "github.com/animacaeli/go-rbac/cache/redis"
	"github.com/animacaeli/go-rbac/core"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/mock"
)

func (s *AuthorizationServiceSuite) consistencyCache() (*miniredis.Miniredis, *rediscache.Cache) {
	mr := miniredis.RunT(s.T())
	cli := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s.T().Cleanup(func() { _ = cli.Close() })
	cch := rediscache.New(cli)
	for _, key := range []string{"rbac:default:epoch", "rbac:!global:epoch", versionKey("10001")} {
		s.Require().NoError(cch.SetIntMax(s.ctx, key, 0))
	}
	s.sut = core.NewAuthorizationService(s.authzRepo, s.counters, cch, nil, nil, time.Minute)
	return mr, cch
}

func (s *AuthorizationServiceSuite) TestConsistency_NewVersionDoesNotJoinOldFlight() {
	// Arrange
	_, cch := s.consistencyCache()
	entered, release := make(chan struct{}), make(chan struct{})
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, "10001").Return(false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, "10001").Return([]string{"user:list"}, nil).Once()
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, "10001").Return([]string(nil), nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, "10001", mock.Anything).Return([]string(nil), nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, "10001", mock.Anything).
		Run(func(mock.Arguments) { close(entered); <-release }).Return((*time.Time)(nil), nil).Once()
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, "10001", mock.Anything).Return((*time.Time)(nil), nil)
	type result struct {
		allowed bool
		err     error
	}
	oldResult, newResult := make(chan result, 1), make(chan result, 1)
	// Act
	go func() { ok, err := s.sut.HasPermission(s.ctx, subject1, "user:list"); oldResult <- result{ok, err} }()
	<-entered
	// Always unblock the old flight, including on assertion failure.
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	s.Require().NoError(cch.SetIntMax(s.ctx, versionKey("10001"), 1))
	go func() { ok, err := s.sut.HasPermission(s.ctx, subject1, "user:list"); newResult <- result{ok, err} }()
	// Assert: new request completes independently while old aggregation is blocked.
	select {
	case got := <-newResult:
		s.Require().NoError(got.err)
		s.False(got.allowed)
	case <-time.After(3 * time.Second):
		s.T().Fatal("new generation joined the blocked old flight")
	}
	close(release)
	select {
	case got := <-oldResult:
		s.Require().NoError(got.err)
		s.False(got.allowed, "version change must retry instead of returning the old result")
	case <-time.After(3 * time.Second):
		s.T().Fatal("old request failed to retry")
	}
}

func (s *AuthorizationServiceSuite) TestConsistency_ExpiryDuringAggregationRetries() {
	// Arrange
	_, _ = s.consistencyCache()
	var expiry time.Time
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, "10001").Return(false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, "10001").Return([]string(nil), nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, "10001", mock.Anything).
		Run(func(a mock.Arguments) { expiry = a.Get(2).(time.Time).Add(20 * time.Millisecond) }).
		Return([]string{"user:list"}, nil).Once()
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, "10001", mock.Anything).Return([]string(nil), nil).Once()
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, "10001", mock.Anything).
		Run(func(mock.Arguments) { time.Sleep(time.Until(expiry) + time.Millisecond) }).Return(&expiry, nil).Once()
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, "10001", mock.Anything).Return((*time.Time)(nil), nil).Once()
	// Act
	allowed, err := s.sut.HasPermission(s.ctx, subject1, "user:list")
	// Assert
	s.Require().NoError(err)
	s.False(allowed)
	allowed, err = s.sut.HasPermission(s.ctx, subject1, "user:list")
	s.Require().NoError(err)
	s.False(allowed, "subsequent cache hit must not resurrect the expired permission")
}

func (s *AuthorizationServiceSuite) TestConsistency_TTLSubtractsAggregationTime() {
	// Arrange
	mr, _ := s.consistencyCache()
	var expiry time.Time
	s.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, "10001").Return(false, nil)
	s.authzRepo.On("EffectiveRolePermissions", mock.Anything, "10001").Return([]string(nil), nil)
	s.authzRepo.On("EffectiveGrantPermissions", mock.Anything, "10001", mock.Anything).
		Run(func(a mock.Arguments) { expiry = a.Get(2).(time.Time).Add(time.Second) }).Return([]string{"user:list"}, nil)
	s.authzRepo.On("NearestGrantExpiry", mock.Anything, "10001", mock.Anything).
		Run(func(mock.Arguments) { time.Sleep(50 * time.Millisecond) }).Return(&expiry, nil)
	// Act
	started := time.Now()
	allowed, err := s.sut.HasPermission(s.ctx, subject1, "user:list")
	// Assert: TTL excludes query time (miniredis does not advance its clock automatically).
	s.Require().NoError(err)
	s.True(allowed)
	s.LessOrEqual(mr.TTL(permKey("10001", 0)), expiry.Sub(started)-50*time.Millisecond)
}
