package rbac_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/registry"
	"gorm.io/gorm"
)

func TestNew_WithoutDB_ReturnsErrDBRequired(t *testing.T) {
	// Act
	app, err := rbac.New()

	// Assert
	requireNilApp(t, app)
	if err == nil {
		t.Fatal("expected error when WithDB is missing")
	}
	if err != rbac.ErrDBRequired && !errors.Is(err, rbac.ErrDBRequired) {
		t.Fatalf("expected ErrDBRequired, got %v", err)
	}
}

func requireNilApp(t *testing.T, app *rbac.App) {
	t.Helper()
	if app != nil {
		t.Fatal("expected nil app")
	}
}

func TestNew_BuiltinPermissionsAutoRegistered(t *testing.T) {
	// Arrange
	reg := registry.NewRegistry()

	// Act
	app, err := rbac.New(rbac.WithDB(&gorm.DB{}), rbac.WithPermissionRegistry(reg))

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, code := range []string{
		"rbac:role:list", "rbac:role:create", "rbac:grant:create", "rbac:audit:read",
	} {
		if !app.Registry().Has(code) {
			t.Errorf("builtin permission %s should be auto-registered", code)
		}
	}
}

func TestApp_ValidatePermissionCodes(t *testing.T) {
	// Arrange
	app, err := rbac.New(
		rbac.WithDB(&gorm.DB{}),
		rbac.WithPermissionRegistry(mustReg(t, registry.New("user:list", "用户列表", "用户管理"))),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Act + Assert
	if err := app.ValidatePermissionCodes("user:list", "rbac:role:list"); err != nil {
		t.Fatalf("registered codes must pass: %v", err)
	}
	err = app.ValidatePermissionCodes("user:list", "user:lst")
	if err == nil {
		t.Fatal("typo code must fail validation")
	}
}

func mustReg(t *testing.T, defs ...registry.PermissionDef) *registry.Registry {
	t.Helper()
	reg := registry.NewRegistry()
	if err := reg.Register(defs...); err != nil {
		t.Fatalf("register: %v", err)
	}
	return reg
}

// stubModule 用于 Module Registry 行为验证。
type stubModule struct {
	name        string
	registerErr error
}

func (m stubModule) Name() string { return m.name }

func (m stubModule) Register(_ *rbac.App) error { return m.registerErr }

func (m stubModule) Migrations() []rbac.Migration {
	return []rbac.Migration{{Module: m.name, Version: "0001", Name: "stub"}}
}

func TestNew_ModuleRegisterError_Propagates(t *testing.T) {
	// Arrange + Act
	app, err := rbac.New(
		rbac.WithDB(&gorm.DB{}),
		rbac.WithModules(stubModule{name: "audit", registerErr: errors.New("dependency missing")}),
	)

	// Assert
	requireNilApp(t, app)
	if err == nil || !strings.Contains(err.Error(), "dependency missing") {
		t.Fatalf("expected module registration error to propagate, got %v", err)
	}
}

func TestNew_ReservedModuleNameRejected(t *testing.T) {
	// Arrange + Act
	app, err := rbac.New(
		rbac.WithDB(&gorm.DB{}),
		rbac.WithModules(stubModule{name: "core"}),
	)

	// Assert
	requireNilApp(t, app)
	if err == nil {
		t.Fatal("module name \"core\" must be rejected")
	}
}
