// Package httpadapter 是 net/http 标准库鉴权适配器（零外部依赖，§3.3）。
//
// 本包完全自包含（逃生舱规则：不共享库内胶水代码，仅依赖 Core 接口）。
//
// 用法：
//
//	guard := httpadapter.New(auth, resolver)
//	mux.Handle("/users", guard.Require("user:list")(http.HandlerFunc(listUsers)))
//
// 401 / 403 / 503 响应可经 WithUnauthorizedHandler 等定制；
// 主体标识经 httpadapter.SubjectFromContext(ctx) 读取。
package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/animacaeli/go-rbac/core"
)

// SubjectContextKey 是主体标识写入 request context 的键。
type SubjectContextKey struct{}

// tenantContextKey 是租户标识写入 request context 的键（仅注入租户解析器时存在）。
type tenantContextKey struct{}

// Guard 是 net/http 鉴权中间件构造器。
type Guard struct {
	authz         core.Authorizer
	resolver      core.SubjectResolver
	tenantResolve TenantResolver // 可选：多租户部署注入
	unauthorized  func(w http.ResponseWriter, r *http.Request, err error)
	forbidden     func(w http.ResponseWriter, r *http.Request)
	unavailable   func(w http.ResponseWriter, r *http.Request, err error)
	metrics       core.Metrics
}

// TenantResolver 由业务项目实现：从已完成认证的可信上下文解析租户标识
// （§2.9）。与 modules/tenant.TenantResolver 形状一致（结构化匹配）。
type TenantResolver = interface {
	ResolveTenant(ctx context.Context) (string, error)
}

// Option 定制 Guard 行为。
type Option func(*Guard)

// WithTenantResolver 注入租户解析器（多租户部署）：请求先解析租户并填入
// AuthorizationContext.TenantID；解析失败按 fail closed 拒绝（403）。
func WithTenantResolver(r TenantResolver) Option {
	return func(g *Guard) {
		if r != nil {
			g.tenantResolve = r
		}
	}
}

// WithUnauthorizedHandler 定制 401 响应。传入 nil 时保持默认实现。
func WithUnauthorizedHandler(h func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(g *Guard) {
		if h != nil {
			g.unauthorized = h
		}
	}
}

// WithForbiddenHandler 定制 403 响应。传入 nil 时保持默认实现。
func WithForbiddenHandler(h func(w http.ResponseWriter, r *http.Request)) Option {
	return func(g *Guard) {
		if h != nil {
			g.forbidden = h
		}
	}
}

// WithUnavailableHandler 定制鉴权服务异常响应（默认 503）。传入 nil 时保持默认实现。
func WithUnavailableHandler(h func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(g *Guard) {
		if h != nil {
			g.unavailable = h
		}
	}
}

// WithMetrics 注入观测实现（DenialsInc 记录 401/403/不可用拒绝计数）。
func WithMetrics(m core.Metrics) Option {
	return func(g *Guard) {
		if m != nil {
			g.metrics = m
		}
	}
}

// New 构造 Guard。
func New(auth core.Authorizer, resolver core.SubjectResolver, opts ...Option) *Guard {
	g := &Guard{
		authz:        auth,
		resolver:     resolver,
		unauthorized: defaultUnauthorized,
		forbidden:    defaultForbidden,
		unavailable:  defaultUnavailable,
		metrics:      core.NoopMetrics{},
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Require 返回要求单个权限码的中间件。空权限码在构造期 panic（必然 503 的
// 调用方编程错误，应在启动期暴露）。
func (g *Guard) Require(code string) func(http.Handler) http.Handler {
	if strings.TrimSpace(code) == "" {
		panic("httpadapter: permission code must not be empty")
	}
	return g.guard(func(ctx context.Context, ac core.AuthorizationContext) (bool, error) {
		return g.authz.HasPermission(ctx, ac, code)
	})
}

// RequireAny 要求任一权限码（OR）。
func (g *Guard) RequireAny(codes ...string) func(http.Handler) http.Handler {
	validateCodes(codes)
	return g.guard(func(ctx context.Context, ac core.AuthorizationContext) (bool, error) {
		if len(codes) == 1 {
			return g.authz.HasPermission(ctx, ac, codes[0])
		}
		return g.authz.HasAnyPermission(ctx, ac, codes...)
	})
}

// RequireAll 要求全部权限码（AND）。
func (g *Guard) RequireAll(codes ...string) func(http.Handler) http.Handler {
	validateCodes(codes)
	return g.guard(func(ctx context.Context, ac core.AuthorizationContext) (bool, error) {
		if len(codes) == 1 {
			return g.authz.HasPermission(ctx, ac, codes[0])
		}
		return g.authz.HasAllPermissions(ctx, ac, codes...)
	})
}

func (g *Guard) guard(eval func(ctx context.Context, ac core.AuthorizationContext) (bool, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 身份解析失败即 401，绝不得视为匿名授权通过（§2.6）；
			// 多租户部署下租户缺失按 fail closed 拒绝（§2.9）。
			subjectID, err := g.resolver.Resolve(r.Context())
			if err != nil {
				g.metrics.DenialsInc("unauthenticated")
				g.unauthorized(w, r, err)
				return
			}
			ac := core.AuthorizationContext{SubjectID: subjectID}
			if g.tenantResolve != nil {
				tenantID, err := g.tenantResolve.ResolveTenant(r.Context())
				if err != nil {
					g.metrics.DenialsInc("forbidden")
					g.forbidden(w, r)
					return
				}
				ac.TenantID = tenantID
			}
			ctx := context.WithValue(r.Context(), SubjectContextKey{}, subjectID.String())
			if g.tenantResolve != nil {
				// 供下游（审计查询、数据范围）读取授权域。
				ctx = context.WithValue(ctx, tenantContextKey{}, ac.TenantID)
				ctx = core.ContextWithTenant(ctx, ac.TenantID)
			}

			ok, err := eval(ctx, ac)
			if err != nil {
				// 账号非活跃 = 确定拒绝（403）；其余异常 fail closed（503）。
				if errors.Is(err, core.ErrSubjectInactive) {
					g.metrics.DenialsInc("forbidden")
					g.forbidden(w, r)
					return
				}
				g.metrics.DenialsInc("unavailable")
				g.unavailable(w, r, err)
				return
			}
			if !ok {
				g.metrics.DenialsInc("forbidden")
				g.forbidden(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// validateCodes 在中间件构造期拒绝空权限码。
func validateCodes(codes []string) {
	if len(codes) == 0 {
		panic("httpadapter: at least one permission code is required")
	}
	for _, code := range codes {
		if strings.TrimSpace(code) == "" {
			panic("httpadapter: permission code must not be empty")
		}
	}
}

// SubjectFromContext 读取 Guard 解析并写入的主体标识。
func SubjectFromContext(ctx context.Context) (core.SubjectID, bool) {
	v, ok := ctx.Value(SubjectContextKey{}).(string)
	if !ok || v == "" {
		return "", false
	}
	return core.SubjectID(v), true
}

// TenantFromContext 读取 Guard 解析并写入的租户标识（仅注入租户解析器时存在）。
func TenantFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(tenantContextKey{}).(string)
	return v, ok
}

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func defaultUnauthorized(w http.ResponseWriter, _ *http.Request, _ error) {
	writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 401, "msg": "unauthenticated"})
}

func defaultForbidden(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusForbidden, map[string]any{"code": 403, "msg": "forbidden"})
}

func defaultUnavailable(w http.ResponseWriter, _ *http.Request, _ error) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": 503, "msg": "authorization unavailable"})
}
