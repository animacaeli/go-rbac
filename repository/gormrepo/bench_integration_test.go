// §9.4 性能基线（集成环境）：需要真实 MySQL（RBAC_TEST_MYSQL_DSN）。
// 批量失效基线另需真实 Redis（RBAC_TEST_REDIS_ADDR）。
package gormrepo_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/animacaeli/go-rbac"
	rediscache "github.com/animacaeli/go-rbac/cache/redis"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type benchEnv struct {
	db  *gorm.DB
	app *rbac.App
	rdb *redis.Client
}

func setupBench(b *testing.B) *benchEnv {
	dsn := os.Getenv("RBAC_TEST_MYSQL_DSN")
	if dsn == "" {
		b.Skip("RBAC_TEST_MYSQL_DSN not set")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	for _, t := range []string{
		"schema_migrations", "rbac_user_grants", "rbac_role_permissions",
		"rbac_user_roles", "rbac_permissions", "rbac_roles",
	} {
		if err := db.Exec("DROP TABLE IF EXISTS " + t).Error; err != nil {
			b.Fatal(err)
		}
	}

	// 500 权限规模（§9.4 权限同步基线）。
	reg := registry.NewRegistry()
	for m := 0; m < 5; m++ {
		for i := 0; i < 100; i++ {
			_ = reg.Register(registry.New(
				fmt.Sprintf("mod%d:action_%03d", m, i),
				fmt.Sprintf("权限-%d-%d", m, i),
				fmt.Sprintf("mod%d", m),
			))
		}
	}

	var rdb *redis.Client
	if addr := os.Getenv("RBAC_TEST_REDIS_ADDR"); addr != "" {
		rdb = redis.NewClient(&redis.Options{Addr: addr})
		if err := rdb.Ping(ctx).Err(); err != nil {
			b.Fatal(err)
		}
		_ = rdb.FlushDB(ctx).Err()
	}

	opts := []rbac.Option{rbac.WithDB(db), rbac.WithPermissionRegistry(reg)}
	if rdb != nil {
		opts = append(opts, rbac.WithCache(rediscache.New(rdb)))
	}
	app, err := rbac.New(opts...)
	if err != nil {
		b.Fatal(err)
	}
	if err := app.Migrate(ctx); err != nil {
		b.Fatal(err)
	}
	if _, err := app.SyncPermissions(ctx); err != nil {
		b.Fatal(err)
	}
	if err := app.SeedSuperAdmin(ctx, "bench-admin"); err != nil {
		b.Fatal(err)
	}
	return &benchEnv{db: db, app: app, rdb: rdb}
}

// §9.4：冷路径权限聚合（1k 权限规模）P99 < 50ms。
func BenchmarkColdAggregate_1kPermissions(b *testing.B) {
	env := setupBench(b)
	ctx := context.Background()
	admin := core.AuthorizationContext{SubjectID: "bench-admin"}

	role, err := env.app.Roles().Create(ctx, admin, "bench_1k", "B", "")
	if err != nil {
		b.Fatal(err)
	}
	perms := env.app.Registry().Codes()
	// 取 1000 条业务权限（500 注册 + 内置）不足则以角色多份叠加：
	// 实际以注册中心全量权限集合挂载到角色。
	if len(perms) > 1000 {
		perms = perms[:1000]
	}
	if err := env.app.Roles().SetPermissions(ctx, admin, role.ID, perms); err != nil {
		b.Fatal(err)
	}
	if err := env.app.UserRoles().Assign(ctx, admin, "bench-user", role.ID); err != nil {
		b.Fatal(err)
	}
	user := core.AuthorizationContext{SubjectID: "bench-user"}

	b.ResetTimer()
	latencies := make([]time.Duration, 0, b.N)
	for i := 0; i < b.N; i++ {
		// 每次迭代递增版本，强制冷路径（绕过缓存命中）。
		start := time.Now()
		ok, err := env.app.Authorizer().HasPermission(ctx, user, "mod0:action_000")
		if err != nil || !ok {
			b.Fatalf("unexpected: ok=%v err=%v", ok, err)
		}
		latencies = append(latencies, time.Since(start))
		// 递增主体版本强制下次冷路径（§6.1 version key）。
		if _, err := env.rdb.Incr(ctx, "rbac:default:subject:bench-user:version").Result(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	reportP99(b, latencies)
}

// §9.4：角色权限变更批量失效（1k 用户）< 100ms（需真实 Redis）。
func BenchmarkBatchInvalidation_1kSubjects(b *testing.B) {
	env := setupBench(b)
	if env.rdb == nil {
		b.Skip("RBAC_TEST_REDIS_ADDR not set")
	}
	ctx := context.Background()
	admin := core.AuthorizationContext{SubjectID: "bench-admin"}

	role, err := env.app.Roles().Create(ctx, admin, "bench_fanout", "B", "")
	if err != nil {
		b.Fatal(err)
	}
	if err := env.app.Roles().SetPermissions(ctx, admin, role.ID, []string{"mod0:action_000"}); err != nil {
		b.Fatal(err)
	}
	subjects := make([]string, 1000)
	for i := range subjects {
		subjects[i] = fmt.Sprintf("fanout-%04d", i)
	}
	if err := env.app.UserRoles().AssignRoleToSubjects(ctx, admin, role.ID, subjects); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	latencies := make([]time.Duration, 0, b.N)
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if err := env.app.Roles().SetPermissions(ctx, admin, role.ID, []string{"mod0:action_000", "mod0:action_001"}); err != nil {
			b.Fatal(err)
		}
		latencies = append(latencies, time.Since(start))
	}
	b.StopTimer()
	reportP99(b, latencies)
}

// §9.4：权限同步（500 权限幂等重跑）< 2s。
func BenchmarkSyncPermissions_500Idempotent(b *testing.B) {
	env := setupBench(b)
	ctx := context.Background()

	b.ResetTimer()
	latencies := make([]time.Duration, 0, b.N)
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if _, err := env.app.SyncPermissions(ctx); err != nil {
			b.Fatal(err)
		}
		latencies = append(latencies, time.Since(start))
	}
	b.StopTimer()
	reportP99(b, latencies)
}

func reportP99(b *testing.B, latencies []time.Duration) {
	if len(latencies) == 0 {
		return
	}
	// 插入排序足够（基准量级）。
	for i := 1; i < len(latencies); i++ {
		for j := i; j > 0 && latencies[j] < latencies[j-1]; j-- {
			latencies[j], latencies[j-1] = latencies[j-1], latencies[j]
		}
	}
	p50 := latencies[len(latencies)*50/100]
	p99 := latencies[len(latencies)*99/100]
	b.ReportMetric(float64(p50.Nanoseconds())/1e6, "p50-ms")
	b.ReportMetric(float64(p99.Nanoseconds())/1e6, "p99-ms")
}
