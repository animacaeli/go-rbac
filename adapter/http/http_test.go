package httpadapter_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/animacaeli/go-rbac/adapter/http"
	"github.com/animacaeli/go-rbac/core"
	coremocks "github.com/animacaeli/go-rbac/test/mocks/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGuard_Require_Authorized_PassesWithSubject(t *testing.T) {
	// Arrange
	authz := coremocks.NewMockAuthorizer(t)
	resolver := coremocks.NewMockSubjectResolver(t)
	resolver.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	authz.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(true, nil)
	guard := httpadapter.New(authz, resolver)

	var gotSubject string
	handler := guard.Require("user:list")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sid, ok := httpadapter.SubjectFromContext(r.Context())
		require.True(t, ok)
		gotSubject = sid.String()
		w.WriteHeader(http.StatusOK)
	}))

	// Act
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users", nil))

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "10001", gotSubject)
}

func TestGuard_Require_AllDenialPaths(t *testing.T) {
	tests := []struct {
		name     string
		resolve  func(*coremocks.MockSubjectResolver)
		authz    func(*coremocks.MockAuthorizer)
		wantCode int
	}{
		{
			name: "resolver_fails_401",
			resolve: func(m *coremocks.MockSubjectResolver) {
				m.On("Resolve", mock.Anything).Return(core.SubjectID(""), errors.New("no auth"))
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "no_permission_403",
			resolve: func(m *coremocks.MockSubjectResolver) {
				m.On("Resolve", mock.Anything).Return(core.SubjectID("1"), nil)
			},
			authz: func(m *coremocks.MockAuthorizer) {
				m.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
					Return(false, nil)
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "subject_inactive_403",
			resolve: func(m *coremocks.MockSubjectResolver) {
				m.On("Resolve", mock.Anything).Return(core.SubjectID("1"), nil)
			},
			authz: func(m *coremocks.MockAuthorizer) {
				m.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
					Return(false, core.ErrSubjectInactive)
			},
			wantCode: http.StatusForbidden,
		},
		{
			name: "authorizer_error_503",
			resolve: func(m *coremocks.MockSubjectResolver) {
				m.On("Resolve", mock.Anything).Return(core.SubjectID("1"), nil)
			},
			authz: func(m *coremocks.MockAuthorizer) {
				m.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
					Return(false, errors.New("db down"))
			},
			wantCode: http.StatusServiceUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			authz := coremocks.NewMockAuthorizer(t)
			resolver := coremocks.NewMockSubjectResolver(t)
			tt.resolve(resolver)
			if tt.authz != nil {
				tt.authz(authz)
			}
			guard := httpadapter.New(authz, resolver)
			handler := guard.Require("user:list")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Fatal("must not reach handler")
			}))

			// Act
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users", nil))

			// Assert
			assert.Equal(t, tt.wantCode, w.Code)
		})
	}
}

func TestGuard_CustomHandlers(t *testing.T) {
	// Arrange
	authz := coremocks.NewMockAuthorizer(t)
	resolver := coremocks.NewMockSubjectResolver(t)
	resolver.On("Resolve", mock.Anything).Return(core.SubjectID("1"), nil)
	authz.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(false, nil)
	guard := httpadapter.New(authz, resolver,
		httpadapter.WithForbiddenHandler(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))

	// Act
	w := httptest.NewRecorder()
	handler := guard.Require("user:list")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users", nil))

	// Assert
	assert.Equal(t, http.StatusTeapot, w.Code)
}

func TestGuard_RequireAnyAndAll(t *testing.T) {
	// Arrange：Any 命中 / All 未命中。
	authz := coremocks.NewMockAuthorizer(t)
	resolver := coremocks.NewMockSubjectResolver(t)
	resolver.On("Resolve", mock.Anything).Return(core.SubjectID("1"), nil).Twice()
	authz.On("HasAnyPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"),
		"a:b", "c:d").Return(true, nil).Once()
	authz.On("HasAllPermissions", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"),
		"a:b", "c:d").Return(false, nil).Once()
	guard := httpadapter.New(authz, resolver)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })

	// Act + Assert
	wAny := httptest.NewRecorder()
	guard.RequireAny("a:b", "c:d")(ok).ServeHTTP(wAny, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, 200, wAny.Code)

	wAll := httptest.NewRecorder()
	guard.RequireAll("a:b", "c:d")(ok).ServeHTTP(wAll, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, http.StatusForbidden, wAll.Code)
}

type httpTenantStub struct{ tenant string }

func (t httpTenantStub) ResolveTenant(context.Context) (string, error) { return t.tenant, nil }

// 租户解析结果写入 request context（审计/数据范围等下游组件依赖）。
func TestGuard_TenantPropagatedToContext(t *testing.T) {
	authz := coremocks.NewMockAuthorizer(t)
	resolver := coremocks.NewMockSubjectResolver(t)
	resolver.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	authz.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(true, nil)
	guard := httpadapter.New(authz, resolver, httpadapter.WithTenantResolver(httpTenantStub{tenant: "acme"}))

	var gotTenant, gotCtxTenant string
	handler := guard.Require("user:list")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant, _ = httpadapter.TenantFromContext(r.Context())
		gotCtxTenant, _ = core.TenantFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "acme", gotTenant)
	assert.Equal(t, "acme", gotCtxTenant)
}

// nil 定制处理器不得导致拒绝时 panic，应回退默认实现。
func TestGuard_NilHandlersFallBackToDefaults(t *testing.T) {
	authz := coremocks.NewMockAuthorizer(t)
	resolver := coremocks.NewMockSubjectResolver(t)
	resolver.On("Resolve", mock.Anything).Return(core.SubjectID("10001"), nil)
	authz.On("HasPermission", mock.Anything, mock.AnythingOfType("core.AuthorizationContext"), "user:list").
		Return(false, nil)
	guard := httpadapter.New(authz, resolver,
		httpadapter.WithForbiddenHandler(nil),
		httpadapter.WithUnauthorizedHandler(nil),
		httpadapter.WithUnavailableHandler(nil),
	)
	handler := guard.Require("user:list")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("protected handler must not run")
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users", nil))

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// 空权限码在构造期暴露（运行时只会得到 503）。
func TestGuard_RequireEmptyCodePanics(t *testing.T) {
	guard := httpadapter.New(coremocks.NewMockAuthorizer(t), coremocks.NewMockSubjectResolver(t))
	assert.Panics(t, func() { guard.Require("") })
	assert.Panics(t, func() { guard.RequireAny() })
	assert.Panics(t, func() { guard.RequireAll("a:b", "") })
}
