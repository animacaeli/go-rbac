package redis_test

import (
	"context"
	"sync"
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

// SetIntMax（P0-1/P0-2 修复的原子原语）：单调护栏——旧值/乱序/损坏均不回退。
func (s *CacheSuite) TestSetIntMax_MonotonicGuard() {
	ctx := s.ctx

	// 空键 → 写入。
	s.Require().NoError(s.sut.SetIntMax(ctx, "k", int64(5)))
	v, ok, err := s.sut.GetInt(ctx, "k")
	s.Require().NoError(err)
	s.True(ok)
	s.Equal(int64(5), v)

	// 较小值 → 不覆盖（P0-1：副本删除后旧操作的同步不得把权威值拉回）。
	s.Require().NoError(s.sut.SetIntMax(ctx, "k", int64(3)))
	v, _, _ = s.sut.GetInt(ctx, "k")
	s.Equal(int64(5), v, "旧值不得覆盖新值")

	// 相等 → 幂等不覆盖。
	s.Require().NoError(s.sut.SetIntMax(ctx, "k", int64(5)))

	// 更大值 → 前进。
	s.Require().NoError(s.sut.SetIntMax(ctx, "k", int64(11)))
	v, _, _ = s.sut.GetInt(ctx, "k")
	s.Equal(int64(11), v)

	// 损坏值（自愈）：不可解析的当前值被权威值覆盖。
	s.srv.Set("k", "corrupt!!!")
	s.Require().NoError(s.sut.SetIntMax(ctx, "k", int64(12)))
	v, _, _ = s.sut.GetInt(ctx, "k")
	s.Equal(int64(12), v, "损坏副本被权威值自愈")
}

// P0-2 场景：恢复（真值 10）与更新同步（真值 11）乱序并发 → 副本只会前进。
func (s *CacheSuite) TestSetIntMax_ConcurrentOutOfOrder_NoRegression() {
	var wg sync.WaitGroup
	order := []int64{10, 11, 9, 12, 8}
	for _, v := range order {
		wg.Add(1)
		go func(val int64) {
			defer wg.Done()
			s.Require().NoError(s.sut.SetIntMax(s.ctx, "race", val))
		}(v)
	}
	wg.Wait()

	v, ok, err := s.sut.GetInt(s.ctx, "race")
	s.Require().NoError(err)
	s.True(ok)
	s.Equal(int64(12), v, "乱序并发后副本 = 最大真值，永不回退")
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
	errSetMax := c.SetIntMax(context.Background(), "ver", 1)

	// Assert
	require.Error(t, errGet)
	require.Error(t, errSetMax)
}

// §4 专项（外部评审第六轮）：损坏值自愈必须是 Lua 原子操作——
// 不允许"先删再写"两步（删除与回填之间的并发同步会看到空键，
// INCR-from-missing 类偏差理论上可注入）。
func (s *CacheSuite) TestSetIntMax_CorruptValue_AtomicSelfHeal() {
	// Arrange：键为损坏字符串。
	s.srv.Set("k", "corrupt!!!")

	// Act：SetIntMax 原子替换（无 Delete 前置）。
	s.Require().NoError(s.sut.SetIntMax(s.ctx, "k", int64(7)))

	// Assert：副本 = 权威真值；整个过程无空键窗口。
	v, ok, err := s.sut.GetInt(s.ctx, "k")
	s.Require().NoError(err)
	s.True(ok)
	s.Equal(int64(7), v)

	// 并发乱序：损坏键被两个不同真值先后写入 → 最大值胜出。
	s.srv.Set("k2", "broken")
	var wg sync.WaitGroup
	for _, val := range []int64{5, 9} {
		wg.Add(1)
		go func(v int64) {
			defer wg.Done()
			_ = s.sut.SetIntMax(s.ctx, "k2", v)
		}(val)
	}
	wg.Wait()
	v2, _, _ := s.sut.GetInt(s.ctx, "k2")
	s.Equal(int64(9), v2, "损坏键上的并发写入收敛到最大真值")
}

// GetInts（批量读）：一次 MGET 区分"缺失"与"值"，损坏值必须报错
// （缓存状态不可信 → 调用方回退数据库权威值）。
func (s *CacheSuite) TestGetInts_BatchSemantics() {
	ctx := s.ctx
	s.Require().NoError(s.sut.SetIntMax(ctx, "a", int64(7)))
	s.Require().NoError(s.sut.SetIntMax(ctx, "c", int64(0)))

	vals, found, err := s.sut.GetInts(ctx, []string{"a", "b", "c"})
	s.Require().NoError(err)
	s.Equal([]int64{7, 0, 0}, vals)
	s.Equal([]bool{true, false, true}, found, "缺失键必须与零值区分")

	s.Require().NoError(s.srv.Set("bad", "not-a-number"))
	_, _, err = s.sut.GetInts(ctx, []string{"a", "bad"})
	s.Require().Error(err, "损坏值必须报错，不得当作未命中")
}
