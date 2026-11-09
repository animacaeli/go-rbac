package ginadapter_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/animacaeli/go-rbac/adapter/gin"
	"github.com/animacaeli/go-rbac/core"
	coremocks "github.com/animacaeli/go-rbac/test/mocks/core"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type GuardSuite struct {
	suite.Suite
	authzMock    *coremocks.MockAuthorizer
	resolverMock *coremocks.MockSubjectResolver
	router       *gin.Engine
	guard        *ginadapter.Guard
}

func (s *GuardSuite) SetupTest() {
	gin.SetMode(gin.TestMode)
	s.authzMock = coremocks.NewMockAuthorizer(s.T())
	s.resolverMock = coremocks.NewMockSubjectResolver(s.T())
	s.guard = ginadapter.New(s.authzMock, s.resolverMock)
	s.router = gin.New()
}

func TestGuardSuite(t *testing.T) { suite.Run(t, new(GuardSuite)) }

// registerRoute 注册一条带 handler 的受保护路由。
func (s *GuardSuite) registerRoute(handler gin.HandlerFunc, final func(c *gin.Context)) *gin.RouterGroup {
	api := s.router.Group("/api")
	api.GET("/protected", handler, final)
	return api
}

func (s *GuardSuite) TestRequire_Authorized_Passes() {
	// Arrange
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	s.authzMock.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(true, nil)
	var gotSubject string
	s.registerRoute(s.guard.Require("user:list"), func(c *gin.Context) {
		sid, ok := ginadapter.GetSubjectID(c)
		s.Require().True(ok)
		gotSubject = sid.String()
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/protected", nil))

	// Assert
	s.Require().Equal(http.StatusOK, w.Code)
	s.Equal("10001", gotSubject)
}

func (s *GuardSuite) TestRequire_ResolverFails_401DefaultBody() {
	// Arrange
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID(""), errors.New("no auth"))
	s.registerRoute(s.guard.Require("user:list"), func(c *gin.Context) {
		c.JSON(http.StatusOK, nil)
	})

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/protected", nil))

	// Assert
	s.Require().Equal(http.StatusUnauthorized, w.Code)
	s.JSONEq(`{"code":401,"msg":"unauthenticated"}`, w.Body.String())
}

func (s *GuardSuite) TestRequire_NoPermission_403DefaultBody() {
	// Arrange
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	s.authzMock.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(false, nil)
	s.registerRoute(s.guard.Require("user:list"), func(c *gin.Context) {
		c.JSON(http.StatusOK, nil)
	})

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/protected", nil))

	// Assert
	s.Require().Equal(http.StatusForbidden, w.Code)
	s.JSONEq(`{"code":403,"msg":"forbidden"}`, w.Body.String())
}

func (s *GuardSuite) TestRequire_AuthorizerError_503FailClosed() {
	// Arrange
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	s.authzMock.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(false, errors.New("db down"))
	s.registerRoute(s.guard.Require("user:list"), func(c *gin.Context) {
		c.JSON(http.StatusOK, nil)
	})

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/protected", nil))

	// Assert：§7.2 失败关闭——服务异常不得放行。
	s.Require().Equal(http.StatusServiceUnavailable, w.Code)
	s.JSONEq(`{"code":503,"msg":"authorization unavailable"}`, w.Body.String())
}

func (s *GuardSuite) TestRequire_SubjectInactive_403Not500() {
	// Arrange
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	s.authzMock.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(false, core.ErrSubjectInactive)
	s.registerRoute(s.guard.Require("user:list"), func(c *gin.Context) {
		c.JSON(http.StatusOK, nil)
	})

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/protected", nil))

	// Assert：§2.6 账号非活跃 → 403，不是服务不可用。
	s.Require().Equal(http.StatusForbidden, w.Code)
}

func (s *GuardSuite) TestRequireAll_MissingOne_403() {
	// Arrange
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	s.authzMock.On("HasAllPermissions", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"),
		"user:list", "user:delete").
		Return(false, nil)
	s.registerRoute(s.guard.RequireAll("user:list", "user:delete"), func(c *gin.Context) {
		c.JSON(http.StatusOK, nil)
	})

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/protected", nil))

	// Assert
	s.Require().Equal(http.StatusForbidden, w.Code)
}

func (s *GuardSuite) TestRequireAny_OneHeld_Passes() {
	// Arrange
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	s.authzMock.On("HasAnyPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"),
		"user:delete", "user:list").
		Return(true, nil)
	s.registerRoute(s.guard.RequireAny("user:delete", "user:list"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/protected", nil))

	// Assert
	s.Require().Equal(http.StatusOK, w.Code)
}

func (s *GuardSuite) TestCustomHandlers_UsedInsteadOfDefaults() {
	// Arrange
	custom := ginadapter.New(
		s.authzMock,
		s.resolverMock,
		ginadapter.WithUnauthorizedHandler(func(c *gin.Context, _ error) {
			c.AbortWithStatusJSON(418, gin.H{"custom": "unauthorized"})
		}),
		ginadapter.WithForbiddenHandler(func(c *gin.Context) {
			c.AbortWithStatusJSON(419, gin.H{"custom": "forbidden"})
		}),
		ginadapter.WithUnavailableHandler(func(c *gin.Context, _ error) {
			c.AbortWithStatusJSON(520, gin.H{"custom": "unavailable"})
		}),
	)
	s.router = gin.New()
	s.router.GET("/p", custom.Require("user:list"), func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil).Times(3)
	// 依次覆盖三种自定义响应：403 → 520 → 200（Once 保证顺序确定）。
	s.authzMock.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(false, nil).Once()
	s.authzMock.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(false, errors.New("boom")).Once()
	s.authzMock.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(true, nil).Once()

	// Act + Assert
	scenarios := []struct {
		name     string
		wantCode int
		wantBody string
	}{
		{"forbidden", 419, `{"custom":"forbidden"}`},
		{"unavailable", 520, `{"custom":"unavailable"}`},
		{"allow", 200, `{"ok":true}`},
	}
	for _, sc := range scenarios {
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/p", nil))
		s.Require().Equalf(sc.wantCode, w.Code, "scenario %s", sc.name)
		s.JSONEqf(sc.wantBody, w.Body.String(), "scenario %s", sc.name)
	}

	// 401 自定义：解析失败。
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID(""), errors.New("no auth")).Once()
	w401 := httptest.NewRecorder()
	s.router.ServeHTTP(w401, httptest.NewRequest(http.MethodGet, "/p", nil))
	s.Require().Equal(418, w401.Code)
	s.JSONEq(`{"custom":"unauthorized"}`, w401.Body.String())
}

func (s *GuardSuite) TestDeclaredCodes_CollectsAllRequireVariants() {
	// Arrange
	s.router.GET("/a", s.guard.Require("user:list"), func(c *gin.Context) {})
	s.router.GET("/b", s.guard.RequireAny("user:delete", "user:update"), func(c *gin.Context) {})
	s.router.GET("/c", s.guard.RequireAll("order:export"), func(c *gin.Context) {})

	// Act
	codes := s.guard.DeclaredCodes()

	// Assert：§2.6 启动期交叉校验的数据源。
	assert.Equal(s.T(), []string{"order:export", "user:delete", "user:list", "user:update"}, codes)
}

func TestGuard_RequireWithoutCodes_Panics(t *testing.T) {
	// Arrange
	gin.SetMode(gin.TestMode)
	authz := coremocks.NewMockAuthorizer(t)
	resolver := coremocks.NewMockSubjectResolver(t)
	guard := ginadapter.New(authz, resolver)

	// Act + Assert
	require.Panics(t, func() { guard.RequireAny() })
	require.Panics(t, func() { guard.RequireAll() })
}

func (s *GuardSuite) TestTenantResolver_MissingTenant_FailClosed() {
	// Arrange
	gin.SetMode(gin.TestMode)
	guard := ginadapter.New(s.authzMock, s.resolverMock,
		ginadapter.WithTenantResolver(fakeTenantResolver{err: errors.New("tenant missing")}))
	s.router = gin.New()
	s.router.GET("/p", guard.Require("user:list"), func(c *gin.Context) { c.JSON(200, nil) })
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	// authz 无任何期望：不得触达授权判断。

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/p", nil))

	// Assert：租户缺失 → fail closed（403），不是 503 也不是放行。
	s.Require().Equal(http.StatusForbidden, w.Code)
}

func (s *GuardSuite) TestTenantResolver_TenantFlowsIntoContext() {
	// Arrange
	guard := ginadapter.New(s.authzMock, s.resolverMock,
		ginadapter.WithTenantResolver(fakeTenantResolver{tenant: "acme"}))
	s.router = gin.New()
	s.router.GET("/p", guard.Require("user:list"), func(c *gin.Context) { c.JSON(200, nil) })
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	// 授权上下文必须携带租户 acme。
	s.authzMock.On("HasPermission", mock.Anything,
		core.AuthorizationContext{SubjectID: "10001", TenantID: "acme"}, "user:list").
		Return(true, nil)

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/p", nil))

	// Assert
	s.Require().Equal(http.StatusOK, w.Code)
}

// fakeTenantResolver 是租户解析器的测试替身（§2.9 fail closed 语义验证）。
type fakeTenantResolver struct {
	tenant string
	err    error
}

func (f fakeTenantResolver) ResolveTenant(context.Context) (string, error) {
	return f.tenant, f.err
}

// 回归：自定义 401/403 handler 只写响应、不调用 Abort 时，Guard 必须自行
// Abort——否则 Gin 会继续执行受保护的业务 handler（fail open）。
func (s *GuardSuite) TestCustomHandlerWithoutAbort_DoesNotRunProtectedHandler() {
	// Arrange
	custom := ginadapter.New(
		s.authzMock,
		s.resolverMock,
		ginadapter.WithForbiddenHandler(func(c *gin.Context) {
			c.Status(http.StatusForbidden) // 刻意不 Abort
		}),
	)
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	s.authzMock.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(false, nil)
	executed := false
	s.router.GET("/p", custom.Require("user:list"), func(c *gin.Context) {
		executed = true
		c.String(http.StatusOK, "secret")
	})

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/p", nil))

	// Assert
	s.Require().Equal(http.StatusForbidden, w.Code)
	s.False(executed, "protected handler must not run after a guard denial")
}

// 回归：租户解析结果写入 request context 与 gin.Context，供下游组件使用。
func (s *GuardSuite) TestTenantResolver_PropagatesTenant() {
	// Arrange
	tenantResolver := tenantStub{tenant: "acme"}
	custom := ginadapter.New(s.authzMock, s.resolverMock, ginadapter.WithTenantResolver(tenantResolver))
	s.resolverMock.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	s.authzMock.On("HasPermission", mock.Anything, mock.MatchedBy(func(ac core.AuthorizationContext) bool {
		return ac.TenantID == "acme"
	}), "user:list").Return(true, nil)
	var gotTenant string
	var gotCtxTenant string
	s.router.GET("/t", custom.Require("user:list"), func(c *gin.Context) {
		gotTenant, _ = ginadapter.GetTenantID(c)
		t, _ := core.TenantFromContext(c.Request.Context())
		gotCtxTenant = t
		c.Status(http.StatusOK)
	})

	// Act
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/t", nil))

	// Assert
	s.Require().Equal(http.StatusOK, w.Code)
	s.Equal("acme", gotTenant)
	s.Equal("acme", gotCtxTenant)
}

type tenantStub struct{ tenant string }

func (t tenantStub) ResolveTenant(context.Context) (string, error) { return t.tenant, nil }
