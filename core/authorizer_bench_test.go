package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/animacaeli/go-rbac/core"
	repositorymocks "github.com/animacaeli/go-rbac/test/mocks/repository"
	"github.com/stretchr/testify/mock"
)

// fakeFastCache 是纯内存高速缓存实现，用于命中路径基准（§9.4：
// 缓存命中路径 HasPermission P99 < 1ms，不含框架开销）。
type fakeFastCache struct {
	strs map[string][]string
	ints map[string]int64
}

func (c *fakeFastCache) Get(_ context.Context, key string) ([]string, bool, error) {
	v, ok := c.strs[key]
	return v, ok, nil
}

func (c *fakeFastCache) Set(_ context.Context, key string, v []string, _ time.Duration) error {
	c.strs[key] = v
	return nil
}

func (c *fakeFastCache) Delete(_ context.Context, key string) error {
	delete(c.strs, key)
	return nil
}

func (c *fakeFastCache) GetInt(_ context.Context, key string) (int64, bool, error) {
	v, ok := c.ints[key]
	return v, ok, nil
}

func (c *fakeFastCache) SetIntMax(_ context.Context, _ string, _ int64) error { return nil }

// BenchmarkHasPermission_CacheHit 测量热路径：GetInt×2 + Get 命中即返回。
func BenchmarkHasPermission_CacheHit(b *testing.B) {
	repo := repositorymocks.NewMockAuthorizationRepo(b)
	repo.On("HasBuiltinSuperAdminRole", mock.Anything, "10001").Return(false, nil).Maybe()
	cch := &fakeFastCache{
		strs: map[string][]string{
			"rbac:default:subject:10001:perm:v0": {"user:list", "order:export"},
		},
		ints: map[string]int64{},
	}
	sut := core.NewAuthorizationService(repo, nil, cch, nil, core.NoopMetrics{}, time.Minute)
	ac := core.AuthorizationContext{SubjectID: "10001"}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := sut.HasPermission(ctx, ac, "user:list")
		if err != nil || !ok {
			b.Fatalf("unexpected: %v %v", ok, err)
		}
	}
}
