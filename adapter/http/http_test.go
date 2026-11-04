package httpadapter_test

import (
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
