// Package ginadapter 是 Gin 框架鉴权适配器（§2.6）。
//
// 本包完全自包含（§3.3 逃生舱规则：不共享库内胶水代码，仅依赖 Core 接口），
// 未来若抽取为子 Module 是机械操作。
//
// 用法：
//
//	guard := ginadapter.New(auth, resolver)
//	api.GET("/users", guard.Require("user:list"), userController.List)
//
// 错误响应可通过 WithUnauthorizedHandler / WithForbiddenHandler /
// WithUnavailableHandler 定制；启动期用 guard.DeclaredCodes() 配合
// rbac.App.ValidatePermissionCodes 做交叉校验。
package ginadapter

import (
	"errors"
	"sort"
	"sync"

	"github.com/animacaeli/go-rbac/core"
	"github.com/gin-gonic/gin"
)

// SubjectContextKey 是主体标识写入 gin.Context 的键。
const SubjectContextKey = "rbac.subject_id"

// Guard 是 Gin 鉴权中间件构造器。
type Guard struct {
	authz        core.Authorizer
	resolver     core.SubjectResolver
	unauthorized func(c *gin.Context, err error)
	forbidden    func(c *gin.Context)
	unavailable  func(c *gin.Context, err error)
	metrics      core.Metrics

	mu       sync.Mutex
	declared map[string]struct{}
}

// Option 定制 Guard 行为。
type Option func(*Guard)

// WithUnauthorizedHandler 定制 401 响应（§2.6 错误响应定制）。
func WithUnauthorizedHandler(h func(c *gin.Context, err error)) Option {
	return func(g *Guard) { g.unauthorized = h }
}

// WithForbiddenHandler 定制 403 响应。
func WithForbiddenHandler(h func(c *gin.Context)) Option {
	return func(g *Guard) { g.forbidden = h }
}

// WithUnavailableHandler 定制鉴权服务异常响应（默认 503）。
func WithUnavailableHandler(h func(c *gin.Context, err error)) Option {
	return func(g *Guard) { g.unavailable = h }
}

// WithMetrics 注入观测实现（DenialsInc 记录 401/403/不可用拒绝计数）。
func WithMetrics(m core.Metrics) Option {
	return func(g *Guard) {
		if m != nil {
			g.metrics = m
		}
	}
}

// New 构造 Guard。auth 为授权服务，resolver 为业务项目的身份解析器。
func New(auth core.Authorizer, resolver core.SubjectResolver, opts ...Option) *Guard {
	g := &Guard{
		authz:        auth,
		resolver:     resolver,
		unauthorized: defaultUnauthorized,
		forbidden:    defaultForbidden,
		unavailable:  defaultUnavailable,
		metrics:      core.NoopMetrics{},
		declared:     make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Require 声明路由所需的单个权限码（全文档统一的中间件签名，§2.6）。
func (g *Guard) Require(code string) gin.HandlerFunc {
	return g.guard(code)
}

// RequireAny 声明路由所需的多个权限码之一（OR 语义）。
func (g *Guard) RequireAny(codes ...string) gin.HandlerFunc {
	return g.guard(codes...)
}

// RequireAll 声明路由必须同时持有的多个权限码（AND 语义）。
func (g *Guard) RequireAll(codes ...string) gin.HandlerFunc {
	return g.guardAll(codes...)
}

func (g *Guard) guard(codes ...string) gin.HandlerFunc {
	if len(codes) == 0 {
		panic("ginadapter: at least one permission code is required")
	}
	g.declare(codes)
	return func(c *gin.Context) {
		subjectID, fail := g.resolve(c)
		if fail {
			return
		}
		ac := core.AuthorizationContext{SubjectID: subjectID}

		var ok bool
		var err error
		switch {
		case len(codes) == 1:
			ok, err = g.authz.HasPermission(c.Request.Context(), ac, codes[0])
		default:
			ok, err = g.authz.HasAnyPermission(c.Request.Context(), ac, codes...)
		}
		g.finish(c, ok, err)
	}
}

func (g *Guard) guardAll(codes ...string) gin.HandlerFunc {
	if len(codes) == 0 {
		panic("ginadapter: at least one permission code is required")
	}
	g.declare(codes)
	return func(c *gin.Context) {
		subjectID, fail := g.resolve(c)
		if fail {
			return
		}
		ac := core.AuthorizationContext{SubjectID: subjectID}

		var ok bool
		var err error
		if len(codes) == 1 {
			ok, err = g.authz.HasPermission(c.Request.Context(), ac, codes[0])
		} else {
			ok, err = g.authz.HasAllPermissions(c.Request.Context(), ac, codes...)
		}
		g.finish(c, ok, err)
	}
}

// resolve 执行身份解析：失败即 401，绝不得视为匿名授权通过（§2.6）。
func (g *Guard) resolve(c *gin.Context) (core.SubjectID, bool) {
	subjectID, err := g.resolver.Resolve(c.Request.Context())
	if err != nil {
		g.metrics.DenialsInc("unauthenticated")
		g.unauthorized(c, err)
		return "", true
	}
	c.Set(SubjectContextKey, subjectID.String())
	return subjectID, false
}

// finish 映射授权结果：非活跃（确定拒绝）→ 403；基础设施错误 → 503（fail closed）。
func (g *Guard) finish(c *gin.Context, ok bool, err error) {
	if err != nil {
		if errors.Is(err, core.ErrSubjectInactive) {
			g.metrics.DenialsInc("forbidden")
			g.forbidden(c)
			return
		}
		g.metrics.DenialsInc("unavailable")
		g.unavailable(c, err)
		return
	}
	if !ok {
		g.metrics.DenialsInc("forbidden")
		g.forbidden(c)
		return
	}
	c.Next()
}

// DeclaredCodes 返回 Guard 已声明的全部权限码（排序去重），
// 供启动期与 Registry 交叉校验（§2.6）。
func (g *Guard) DeclaredCodes() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.declared))
	for code := range g.declared {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

func (g *Guard) declare(codes []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, code := range codes {
		g.declared[code] = struct{}{}
	}
}

// ---- 默认响应（未注入处理器时使用，§2.6） ----

func defaultUnauthorized(c *gin.Context, _ error) {
	c.AbortWithStatusJSON(401, gin.H{"code": 401, "msg": "unauthenticated"})
}

func defaultForbidden(c *gin.Context) {
	c.AbortWithStatusJSON(403, gin.H{"code": 403, "msg": "forbidden"})
}

func defaultUnavailable(c *gin.Context, _ error) {
	c.AbortWithStatusJSON(503, gin.H{"code": 503, "msg": "authorization unavailable"})
}
