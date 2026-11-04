// gin-tenant：go-rbac 多租户 + 菜单 + 数据范围接入示例（§2.7/§2.8/§2.9）。
//
// 演示要点：
//   - tenant 模块注册在首位；请求入口解析租户并注入 ctx（缺失即 fail closed）
//   - 平台超管（default 域）与租户超管的边界
//   - 菜单可见树与数据范围解析按授权域隔离
//
// 运行（先 docker compose up -d）：
//
//	export RBAC_DSN='root:rootpass@tcp(127.0.0.1:3306)/go_rbac_tenant_demo?parseTime=true&loc=UTC&charset=utf8mb4'
//	export RBAC_ADDR=:18082
//	go run ./examples/gin-tenant
//
// 验证（同时携带两个头：身份 + 租户；生产中两者均须来自已认证上下文）：
//
//	# acme 租户超管：本域恒真 + 可见全部菜单
//	curl -H 'X-Subject-ID: acme-admin' -H 'X-Tenant-ID: acme' localhost:18082/api/whoami
//	# 平台超管：携带任意租户上下文均恒真
//	curl -H 'X-Subject-ID: platform-admin' -H 'X-Tenant-ID: acme' localhost:18082/api/whoami
//	# 缺租户头：fail closed（403）
//	curl -H 'X-Subject-ID: acme-admin' localhost:18082/api/whoami
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/animacaeli/go-rbac"
	ginadapter "github.com/animacaeli/go-rbac/adapter/gin"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/modules/datascope"
	"github.com/animacaeli/go-rbac/modules/menu"
	"github.com/animacaeli/go-rbac/modules/tenant"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type subjectCtxKey struct{}
type tenantCtxKey struct{}

// subjectResolver / tenantResolver 均从"业务已认证的可信上下文"取值（§4.2/§4.4）。
// 演示版直接读中间件注入的头；生产中应来自 JWT claims / Session 等可信来源，
// 绝不可取自未验证的请求参数。
type subjectResolver struct{}

func (subjectResolver) Resolve(ctx context.Context) (core.SubjectID, error) {
	v, ok := ctx.Value(subjectCtxKey{}).(string)
	if !ok || v == "" {
		return "", errUnauthenticated
	}
	return core.SubjectID(v), nil
}

type tenantResolver struct{}

func (tenantResolver) ResolveTenant(ctx context.Context) (string, error) {
	v, ok := ctx.Value(tenantCtxKey{}).(string)
	if !ok || v == "" {
		// §2.9：TenantID 缺失 = fail closed，不得回退 default 域。
		return "", errTenantMissing
	}
	return v, nil
}

type unauthenticatedError struct{}

func (unauthenticatedError) Error() string { return "missing subject" }

type tenantMissingError struct{}

func (tenantMissingError) Error() string { return "missing tenant" }

var (
	errUnauthenticated = unauthenticatedError{}
	errTenantMissing   = tenantMissingError{}
)

func main() {
	ctx := context.Background()

	db, err := gorm.Open(mysql.Open(mustEnv("RBAC_DSN")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		slog.Error("connect database failed", "err", err)
		os.Exit(1)
	}

	permissions := registry.NewRegistry()
	mustRegister(permissions,
		registry.New("order:list", "订单列表", "订单管理"),
		registry.New("order:export", "导出订单", "订单管理"),
	)

	// tenant 模块必须注册在首位（其他模块经 App 惰性取被替换后的服务）。
	tenantMod := tenant.New()
	menuMod := menu.New()
	dsMod := datascope.New()
	app, err := rbac.New(
		rbac.WithDB(db),
		rbac.WithPermissionRegistry(permissions),
		rbac.WithModules(tenantMod, menuMod, dsMod),
	)
	if err != nil {
		slog.Error("rbac init failed", "err", err)
		os.Exit(1)
	}
	// 迁移包含 §5.5 租户契约（加列 → 回填 → 重建三唯一键）。
	if err := app.Migrate(ctx); err != nil {
		slog.Error("migrate failed", "err", err)
		os.Exit(1)
	}
	if _, err := app.SyncPermissions(ctx); err != nil {
		slog.Error("sync permissions failed", "err", err)
		os.Exit(1)
	}

	// 种子：平台超管（default 域，全租户生效）+ 两个租户超管（仅本域）。
	if err := app.SeedSuperAdmin(ctx, "platform-admin"); err != nil {
		slog.Error("seed platform super admin failed", "err", err)
		os.Exit(1)
	}
	for _, t := range []string{"acme", "beta"} {
		if err := tenantMod.SeedSuperAdminInTenant(ctx, t, t+"-admin"); err != nil {
			slog.Error("seed tenant super admin failed", "err", err, "tenant", t)
			os.Exit(1)
		}
	}

	// 声明菜单（全局定义；可见性按主体权限解析）。
	if err := menuMod.Declare(ctx,
		menu.Item{Code: "biz", Name: "业务", Type: menu.TypeDirectory},
		menu.Item{Code: "orders", Parent: "biz", Name: "订单", Type: menu.TypePage,
			Path: "/orders", Component: "OrderList", Permissions: []string{"order:list"}},
	); err != nil {
		slog.Error("declare menus failed", "err", err)
		os.Exit(1)
	}

	// 多租户部署：guard 同时解析身份与租户（缺失即 fail closed，§2.9）。
	tResolver := tenantResolver{}
	guard := ginadapter.New(app.Authorizer(), subjectResolver{},
		ginadapter.WithTenantResolver(tResolver))

	r := gin.Default()
	// 请求入口：解析身份与租户，注入可信上下文（授权与租户隔离均以此为源）。
	r.Use(func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), subjectCtxKey{}, c.GetHeader("X-Subject-ID"))
		ctx = context.WithValue(ctx, tenantCtxKey{}, c.GetHeader("X-Tenant-ID"))
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})

	api := r.Group("/api")
	api.GET("/orders", guard.Require("order:list"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"orders": []string{"o1", "o2"}})
	})

	// 自省：身份 + 超管判定 + 可见菜单 + 订单数据范围（全部按当前租户域解析）。
	api.GET("/whoami", func(c *gin.Context) {
		reqCtx := c.Request.Context()
		subject, err := subjectResolver{}.Resolve(reqCtx)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "unauthenticated"})
			return
		}
		tenantID, err := tResolver.ResolveTenant(reqCtx)
		if err != nil {
			// 租户缺失 → fail closed（§2.9）。
			c.JSON(http.StatusForbidden, gin.H{"code": 403, "msg": "tenant context required"})
			return
		}
		ac := core.AuthorizationContext{TenantID: tenantID, SubjectID: subject}
		isSuper, err := app.Authorizer().IsSuperAdministrator(reqCtx, ac)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"code": 403, "msg": err.Error()})
			return
		}
		menus, err := menuMod.ResolveVisibleMenus(reqCtx, ac)
		if err != nil {
			slog.Error("menus resolve failed", "err", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"err": err.Error()})
			return
		}
		scope, err := dsMod.ResolveDataScope(reqCtx, ac, "order")
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"err": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"tenant": tenantID, "subject": subject, "is_super": isSuper,
			"menus": menus, "order_data_scope": scope.String(),
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
	slog.Info("gin-tenant listening", "addr", addr)
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
