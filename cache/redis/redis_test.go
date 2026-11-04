package redis_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	rediscache "github.com/animacaeli/go-rbac/cache/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type CacheSuite struct {
	suite.Suite
	ctx context.Context
	srv *miniredis.Miniredis
	sut *rediscache.Cache
}

func (s *CacheSuite) SetupTest() {
	s.ctx = context.Background()
	srv := miniredis.RunT(s.T())
	s.srv = srv
	s.sut = rediscache.New(redis.NewClient(&redis.Options{Addr: srv.Addr()}))
}

func TestCacheSuite(t *testing.T) { suite.Run(t, new(CacheSuite)) }

func (s *CacheSuite) TestSetGet_RoundTrip() {
	// Arrange
	perms := []string{"user:list", "order:export"}

	// Act
	s.Require().NoError(s.sut.Set(s.ctx, "k", perms, time.Minute))
	got, ok, err := s.sut.Get(s.ctx, "k")

	// Assert
	s.Require().NoError(err)
	s.True(ok)
	s.Equal(perms, got)
}

func (s *CacheSuite) TestGet_MissingKey_NotHitNoError() {
	// Act
	got, ok, err := s.sut.Get(s.ctx, "missing")

	// Assert
	s.Require().NoError(err)
	s.False(ok)
	s.Nil(got)
}

func (s *CacheSuite) TestGet_CorruptedValue_TreatedAsMiss() {
	// Arrange：直接写入损坏 JSON。
	s.Require().NoError(s.sut.Set(s.ctx, "k", []string{"x"}, time.Minute))
	s.srv.Set("k", "{not-json")

	// Act
	got, ok, err := s.sut.Get(s.ctx, "k")

	// Assert：损坏值视同未命中，不向上抛错（回源后写回自愈）。
	s.Require().NoError(err)
	s.False(ok)
	s.Nil(got)
}

func (s *CacheSuite) TestSet_TTLApplied() {
	// Act
	s.Require().NoError(s.sut.Set(s.ctx, "k", []string{"a"}, 2*time.Second))
	ttl := s.srv.TTL("k")

	// Assert
	s.Greater(ttl, time.Second)
	s.LessOrEqual(ttl, 2*time.Second)
}

func (s *CacheSuite) TestDelete() {
	// Arrange
	s.Require().NoError(s.sut.Set(s.ctx, "k", []string{"a"}, time.Minute))

	// Act
	s.Require().NoError(s.sut.Delete(s.ctx, "k"))
	_, ok, err := s.sut.Get(s.ctx, "k")

	// Assert
	s.Require().NoError(err)
	s.False(ok)
}

func (s *CacheSuite) TestGetInt_MissingKey_ZeroNotOk() {
	// Act
	v, ok, err := s.sut.GetInt(s.ctx, "ver")

	// Assert
	s.Require().NoError(err)
	s.False(ok)
	s.Zero(v)
}

func (s *CacheSuite) TestIncr_AtomicFromZero() {
	// Act + Assert
	v1, err := s.sut.Incr(s.ctx, "ver")
	s.Require().NoError(err)
	s.Equal(int64(1), v1)

	v2, err := s.sut.Incr(s.ctx, "ver")
	s.Require().NoError(err)
	s.Equal(int64(2), v2)

	got, ok, err := s.sut.GetInt(s.ctx, "ver")
	s.Require().NoError(err)
	s.True(ok)
	s.Equal(int64(2), got)
}

func (s *CacheSuite) TestIncr_Concurrent() {
	// Arrange：并发递增 100 次，结果必须是精确的 100。
	const n = 100

	// Act
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			_, err := s.sut.Incr(s.ctx, "ver")
			s.Require().NoError(err)
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}

	// Assert
	v, ok, err := s.sut.GetInt(s.ctx, "ver")
	s.Require().NoError(err)
	s.True(ok)
	s.Equal(int64(n), v)
}

func TestCache_ServerDown_ErrorSurfaces(t *testing.T) {
	// Arrange：连接一个必然被拒绝的地址（127.0.0.1:1，Dial 快速失败）。
	c := rediscache.New(redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 100 * time.Millisecond,
	}))

	// Act：错误必须向上抛（§6.6：鉴权路径回源、管理接口报错由上层决定）。
	_, _, errGet := c.Get(context.Background(), "k")
	_, errIncr := c.Incr(context.Background(), "ver")

	// Assert
	require.Error(t, errGet)
	require.Error(t, errIncr)
}
