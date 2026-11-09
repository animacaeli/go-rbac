// 真实 Redis 原语集成套件（第九轮复审 P2）。
//
// 单元套件（miniredis）验证逻辑；本套件在**真实 Redis 7**上验证 Lua 脚本、
// MGET 与故障语义——miniredis 的 Lua/协议行为是近似实现，不能替代真实实例。
//
// 环境变量门控：RBAC_TEST_REDIS_ADDR（make test-integration / CI 提供）。
// 只使用 "real-itest:" 前缀并在每个用例前清理，避免与同包其它套件互相干扰。
package redis_test

import (
	"context"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	rediscache "github.com/animacaeli/go-rbac/cache/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/suite"
)

const realKeyPrefix = "real-itest:"

func TestRealRedisSuite(t *testing.T) {
	if os.Getenv("RBAC_TEST_REDIS_ADDR") == "" {
		t.Skip("RBAC_TEST_REDIS_ADDR not set; skipping real Redis primitive tests")
	}
	suite.Run(t, new(RealRedisSuite))
}

type RealRedisSuite struct {
	suite.Suite
	ctx context.Context
	rdb *redis.Client
	sut *rediscache.Cache
}

func (s *RealRedisSuite) SetupSuite() {
	s.ctx = context.Background()
	s.rdb = redis.NewClient(&redis.Options{Addr: os.Getenv("RBAC_TEST_REDIS_ADDR")})
	s.Require().NoError(s.rdb.Ping(s.ctx).Err(), "真实 Redis 不可达（RBAC_TEST_REDIS_ADDR）")
	s.sut = rediscache.New(s.rdb)
}

func (s *RealRedisSuite) TearDownSuite() {
	if s.rdb != nil {
		s.Require().NoError(s.rdb.Close())
	}
}

func (s *RealRedisSuite) SetupTest() {
	var cursor uint64
	for {
		keys, next, err := s.rdb.Scan(s.ctx, cursor, realKeyPrefix+"*", 200).Result()
		s.Require().NoError(err)
		if len(keys) > 0 {
			s.Require().NoError(s.rdb.Del(s.ctx, keys...).Err())
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
}

// Lua 单调写：真实脚本对 2^53 / int64 上限必须精确，不得回退。
func (s *RealRedisSuite) TestSetIntMax_ExactAndMonotonic() {
	const p53 = int64(1) << 53
	const maxInt64 = int64(^uint64(0) >> 1)
	key := realKeyPrefix + "mono"

	for _, v := range []int64{0, p53, p53 - 1, p53 + 1, maxInt64, maxInt64 - 1} {
		s.Require().NoError(s.sut.SetIntMax(s.ctx, key, v))
		got, ok, err := s.sut.GetInt(s.ctx, key)
		s.Require().NoError(err)
		s.True(ok)
		s.GreaterOrEqual(got, v, "副本只能单调前进")
	}
	got, _, _ := s.sut.GetInt(s.ctx, key)
	s.Equal(maxInt64, got)

	s.Require().Error(s.sut.SetIntMax(s.ctx, key, -1), "负数写入必须拒绝")
}

// 损坏值自愈：真实 Lua 的 string.match/字符串比较路径。
func (s *RealRedisSuite) TestSetIntMax_CorruptValueSelfHeals() {
	key := realKeyPrefix + "corrupt"
	for _, bad := range []string{"12x3", "-7", " 42", "1e10"} {
		s.Require().NoError(s.rdb.Set(s.ctx, key, bad, 0).Err())
		s.Require().NoError(s.sut.SetIntMax(s.ctx, key, 5))
		got, ok, err := s.sut.GetInt(s.ctx, key)
		s.Require().NoError(err)
		s.True(ok)
		s.Equal(int64(5), got, "损坏值 %q 必须被原子替换", bad)
	}
}

// 并发乱序写入必须收敛到最大值（真实 Lua 原子性 + 单调护栏）。
func (s *RealRedisSuite) TestSetIntMax_ConcurrentOutOfOrder() {
	key := realKeyPrefix + "concurrent"
	const workers = 8
	const rounds = 200
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed)) //nolint:gosec // 测试用
			vals := r.Perm(1000)
			for _, n := range vals[:rounds] {
				if err := s.sut.SetIntMax(s.ctx, key, int64(n)+1); err != nil {
					errCh <- err
					return
				}
			}
		}(int64(w))
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		s.Require().NoError(err)
	}
	got, ok, err := s.sut.GetInt(s.ctx, key)
	s.Require().NoError(err)
	s.True(ok)
	s.Equal(int64(1000), got, "所有写入结束后副本必须等于最大值")
}

// MGET 批量读：缺失键与零值必须区分；任一损坏值必须报错。
func (s *RealRedisSuite) TestGetInts_RealMGet() {
	s.Require().NoError(s.rdb.Set(s.ctx, realKeyPrefix+"a", 7, 0).Err())
	s.Require().NoError(s.rdb.Set(s.ctx, realKeyPrefix+"c", 0, 0).Err())

	vals, found, err := s.sut.GetInts(s.ctx, []string{realKeyPrefix + "a", realKeyPrefix + "b", realKeyPrefix + "c"})
	s.Require().NoError(err)
	s.Equal([]int64{7, 0, 0}, vals)
	s.Equal([]bool{true, false, true}, found)

	s.Require().NoError(s.rdb.Set(s.ctx, realKeyPrefix+"bad", "x", 0).Err())
	_, _, err = s.sut.GetInts(s.ctx, []string{realKeyPrefix + "a", realKeyPrefix + "bad"})
	s.Require().Error(err)
}

// 损坏 JSON 视为未命中（由写回覆盖修复）。
func (s *RealRedisSuite) TestGet_CorruptJSONIsMiss() {
	key := realKeyPrefix + "json"
	s.Require().NoError(s.rdb.Set(s.ctx, key, "{not-json", 0).Err())
	perms, ok, err := s.sut.Get(s.ctx, key)
	s.Require().NoError(err)
	s.False(ok)
	s.Nil(perms)
}

// 连接故障：所有原语必须返回错误而不是 panic / 假成功。
func (s *RealRedisSuite) TestFailureSemantics_NoPanic() {
	bad := redis.NewClient(&redis.Options{
		Addr:         "127.0.0.1:1", // 无服务监听
		DialTimeout:  100 * time.Millisecond,
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		MaxRetries:   -1,
	})
	s.T().Cleanup(func() { _ = bad.Close() })
	sut := rediscache.New(bad)

	_, _, err := sut.Get(s.ctx, "k")
	s.Error(err, "Get 必须返回错误")

	_, _, err = sut.GetInt(s.ctx, "k")
	s.Error(err, "GetInt 必须返回错误")

	_, _, err = sut.GetInts(s.ctx, []string{"k1", "k2"})
	s.Error(err, "GetInts 必须返回错误")

	s.Error(sut.Set(s.ctx, "k", []string{"x"}, time.Minute), "Set 必须返回错误")
	s.Error(sut.Delete(s.ctx, "k"), "Delete 必须返回错误")
	s.Error(sut.SetIntMax(s.ctx, "k", 1), "SetIntMax 必须返回错误")
}
