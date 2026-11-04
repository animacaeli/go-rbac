// gin-basic：go-rbac 最小可运行接入示例（§10 验收标准）。
//
// 运行（先启动 docker-compose.yml 中的 MySQL）：
//
//	export RBAC_DSN='root:rootpass@tcp(127.0.0.1:3306)/go_rbac?parseTime=true&loc=UTC&charset=utf8mb4'
//	export RBAC_SUPER_ADMIN=10001
//	go run ./examples/gin-basic
//
// 然后以 X-Subject-ID 头模拟已认证身份（仅演示！生产环境身份必须来自
// 业务项目已完成认证的可信上下文，§4.2）：
//
//	curl -H 'X-Subject-ID: 10001' http://localhost:8080/api/users      # 超管，200
//	curl -H 'X-Subject-ID: 20001' http://localhost:8080/api/users      # 有角色授权，200
//	curl -H 'X-Subject-ID: 30001' http://localhost:8080/api/users      # 无权限，403
//	curl http://localhost:8080/api/users                               # 未认证，401
//	curl -H 'X-Subject-ID: 10001' http://localhost:8080/api/permissions # 超管查看自身权限
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/animacaeli/go-rbac"
	ginadapter "github.com/animacaeli/go-rbac/adapter/gin"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// subjectCtxKey 是业务侧自定义的 context key（身份解析器读取）。
type subjectCtxKey struct{}

// headerSubjectResolver 演示身份解析器：从业务中间件写入的可信上下文取身份。
// 真实项目中这里应读取 JWT claims / session 等已认证信息。
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

	// 1. 业务数据库连接（DSN 建议 parseTime=true&loc=UTC，§5.1）。
	db, err := gorm.Open(mysql.Open(mustEnv("RBAC_DSN")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		slog.Error("connect database failed", "err", err)
		os.Exit(1)
	}

	// 2. 声明业务权限资源（§2.3）。
	permissions := registry.NewRegistry()
	mustRegister(permissions,
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("user:create", "创建用户", "用户管理"),
		registry.New("order:list", "订单列表", "订单管理"),
		registry.New("order:export", "导出订单", "订单管理"),
	)

	// 3. 组装 RBAC（New 无副作用：不迁移、不触库，§4.1）。
	app, err := rbac.New(
		rbac.WithDB(db),
		rbac.WithPermissionRegistry(permissions),
		// rbac.WithSubjectStatusChecker(myChecker),  // 可选：账号状态检查
		// rbac.WithCache(redisCache),                // 可选：Phase 2 起提供 Redis 实现
	)
	if err != nil {
		slog.Error("rbac init failed", "err", err)
		os.Exit(1)
	}

	// 4. 显式迁移 + 权限同步（幂等，可重复执行）。
	if err := app.Migrate(ctx); err != nil {
		slog.Error("migrate failed", "err", err)
		os.Exit(1)
	}
	if _, err := app.SyncPermissions(ctx); err != nil {
		slog.Error("sync permissions failed", "err", err)
		os.Exit(1)
	}

	// 5. 超管种子：唯一的超管授予入口（§7.3，管理接口不可授予）。
	if super := os.Getenv("RBAC_SUPER_ADMIN"); super != "" {
		if err := app.SeedSuperAdmin(ctx, super); err != nil {
			slog.Error("seed super admin failed", "err", err)
			os.Exit(1)
		}
	}

	// 6. 演示数据：普通角色 + 角色授权 + 用户绑定（超管操作豁免持权约束）。
	seedDemoData(ctx, app)

	// 7. 构造 Gin 鉴权中间件。
	guard := ginadapter.New(app.Authorizer(), headerSubjectResolver{})

	r := gin.Default()

	// 业务认证中间件（演示版）：把"已认证身份"写入 request context。
	// 真实项目中此步是 JWT 校验 / Session 检查。
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
	api.POST("/users", guard.Require("user:create"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"created": true})
	})
	api.GET("/orders/export", guard.Require("order:export"), func(c *gin.Context) {
		subject, _ := ginadapter.GetSubjectID(c)
		c.JSON(http.StatusOK, gin.H{"exported_for": subject})
	})
	// 身份自省接口：仅需认证，不要求具体权限——直接用解析器取身份。
	resolver := headerSubjectResolver{}
	api.GET("/whoami", func(c *gin.Context) {
		subject, err := resolver.Resolve(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "unauthenticated"})
			return
		}
		ac := core.AuthorizationContext{SubjectID: subject}
		isSuper, err := app.Authorizer().IsSuperAdministrator(c.Request.Context(), ac)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"err": err.Error()})
			return
		}
		perms, err := app.Authorizer().GetPermissions(c.Request.Context(), ac)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"err": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"subject": subject, "is_super_admin": isSuper, "permissions": perms})
	})

	// 8. 启动期权限码交叉校验（§2.6）：拼写错误在此 fail fast，而非运行时永远 403。
	if err := app.ValidatePermissionCodes(guard.DeclaredCodes()...); err != nil {
		slog.Error("undeclared permission codes on routes", "err", err)
		os.Exit(1)
	}

	addr := os.Getenv("RBAC_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	slog.Info("gin-basic listening", "addr", addr)
	if err := r.Run(addr); err != nil {
		slog.Error("server exited", "err", err)
	}
}

// seedDemoData 幂等地准备演示角色与授权。
func seedDemoData(ctx context.Context, app *rbac.App) {
	super := core.AuthorizationContext{SubjectID: core.SubjectID(mustEnv("RBAC_SUPER_ADMIN"))}

	role, err := app.Roles().FindByCode(ctx, "operator")
	if err != nil {
		role, err = app.Roles().Create(ctx, super, "operator", "运营专员", "演示角色")
		if err != nil {
			slog.Warn("seed demo role failed", "err", err)
			return
		}
	}
	if err := app.Roles().SetPermissions(ctx, super, role.ID, []string{"user:list", "user:create"}); err != nil {
		slog.Warn("seed demo permissions failed", "err", err)
		return
	}
	if err := app.UserRoles().Assign(ctx, super, "20001", role.ID); err != nil {
		slog.Warn("seed demo assignment failed", "err", err)
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
