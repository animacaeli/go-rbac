// gin-redis：go-rbac + Redis 权限缓存接入示例（§6 / Phase 2 能力演示）。
//
// 与 gin-basic 的差异：注入 Redis 缓存（版本号 + epoch 两级失效），
// 并用 core.CountingMetrics 暴露命中/未命中观测数据。
//
// 运行（先 docker compose up -d，Redis 映射在宿主 6380）：
//
//	export RBAC_DSN='root:rootpass@tcp(127.0.0.1:3306)/go_rbac?parseTime=true&loc=UTC&charset=utf8mb4'
//	export RBAC_SUPER_ADMIN=10001
//	export RBAC_ADDR=:18081
//	go run ./examples/gin-redis
//
// 验证缓存生效（两次 /whoami 后 metrics 的 cache_hits 递增）：
//
//	curl -H 'X-Subject-ID: 10001' localhost:18081/api/whoami
//	curl -H 'X-Subject-ID: 10001' localhost:18081/api/whoami
//	curl -H 'X-Subject-ID: 10001' localhost:18081/admin/metrics
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/animacaeli/go-rbac"
	ginadapter "github.com/animacaeli/go-rbac/adapter/gin"
	rediscache "github.com/animacaeli/go-rbac/cache/redis"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type subjectCtxKey struct{}

type headerSubjectResolver struct{}

func (headerSubjectResolver) Resolve(ctx context.Context) (core.SubjectID, error) {
	v, ok := ctx.Value(subjectCtxKey{}).(string)
	if !ok || v == "" {
		return "", errUnauthenticated
	}
	return core.SubjectID(v), nil
}

type unauthenticatedError struct{}

func (unauthenticatedError) Error() string { return "missing subject" }

var errUnauthenticated = unauthenticatedError{}

func main() {
	ctx := context.Background()

	db, err := gorm.Open(mysql.Open(mustEnv("RBAC_DSN")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		slog.Error("connect database failed", "err", err)
		os.Exit(1)
	}

	redisAddr := os.Getenv("RBAC_REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6380"
	}
	rdb := goredis.NewClient(&goredis.Options{Addr: redisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("connect redis failed", "err", err, "addr", redisAddr)
		os.Exit(1)
	}

	permissions := registry.NewRegistry()
	mustRegister(permissions,
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("order:export", "导出订单", "订单管理"),
	)

	// 与 gin-basic 的关键差异：WithCache 注入 Redis 适配器 + 观测实现。
	metrics := core.NewCountingMetrics()
	app, err := rbac.New(
		rbac.WithDB(db),
		rbac.WithPermissionRegistry(permissions),
		rbac.WithCache(rediscache.New(rdb)),
		rbac.WithCacheTTL(10*time.Minute),
		rbac.WithMetrics(metrics),
	)
	if err != nil {
		slog.Error("rbac init failed", "err", err)
		os.Exit(1)
	}
	if err := app.Migrate(ctx); err != nil {
		slog.Error("migrate failed", "err", err)
		os.Exit(1)
	}
	if _, err := app.SyncPermissions(ctx); err != nil {
		slog.Error("sync permissions failed", "err", err)
		os.Exit(1)
	}
	if super := os.Getenv("RBAC_SUPER_ADMIN"); super != "" {
		if err := app.SeedSuperAdmin(ctx, super); err != nil {
			slog.Error("seed super admin failed", "err", err)
			os.Exit(1)
		}
	}

	guard := ginadapter.New(app.Authorizer(), headerSubjectResolver{}, ginadapter.WithMetrics(metrics))

	r := gin.Default()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(
			context.WithValue(c.Request.Context(), subjectCtxKey{}, c.GetHeader("X-Subject-ID")),
		)
		c.Next()
	})

	api := r.Group("/api")
	api.GET("/users", guard.Require("user:list"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"users": []string{"u1", "u2"}})
	})
	api.GET("/whoami", func(c *gin.Context) {
		subject, err := headerSubjectResolver{}.Resolve(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "unauthenticated"})
			return
		}
		ac := core.AuthorizationContext{SubjectID: subject}
		perms, err := app.Authorizer().GetPermissions(c.Request.Context(), ac)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"err": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"subject": subject, "permissions": perms})
	})

	// 观测出口：缓存命中/未命中、拒绝计数、平均耗时（业务可换成 Prometheus）。
	r.GET("/admin/metrics", guard.Require("rbac:role:list"), func(c *gin.Context) {
		snap := metrics.Snapshot()
		c.JSON(http.StatusOK, gin.H{
			"cache_hits":   snap.CacheHits,
			"cache_misses": snap.CacheMisses,
			"denials":      snap.Denials,
			"p50ish":       snap.AvgDuration.String(),
		})
	})

	if err := app.ValidatePermissionCodes(guard.DeclaredCodes()...); err != nil {
		slog.Error("undeclared permission codes on routes", "err", err)
		os.Exit(1)
	}

	addr := os.Getenv("RBAC_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	slog.Info("gin-redis listening", "addr", addr, "redis", redisAddr)
	if err := r.Run(addr); err != nil {
		slog.Error("server exited", "err", err)
	}
}

func mustRegister(reg *registry.Registry, defs ...registry.PermissionDef) {
	if err := reg.Register(defs...); err != nil {
		slog.Error("register permissions failed", "err", err)
		os.Exit(1)
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("missing required env", "key", key)
		os.Exit(1)
	}
	return v
}
