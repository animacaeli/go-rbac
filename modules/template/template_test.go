package template_test

import (
	"testing"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/modules/template"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestModule_Register_UnregisteredPermission_FailsFast(t *testing.T) {
	// Arrange：模板引用了未注册的权限码。
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(registry.New("user:list", "用户列表", "用户管理")))
	tpl := template.New(
		template.Define("ops", "运营", "desc", "user:list", "typo:code"),
	)

	// Act
	_, err := rbac.New(rbac.WithDB(&gorm.DB{}), rbac.WithPermissionRegistry(reg), rbac.WithModules(tpl))

	// Assert：fail fast（§3.3 模块注册期依赖检查）。
	require.Error(t, err)
	require.Contains(t, err.Error(), "typo:code")
}

func TestModule_Register_ValidTemplates_Succeeds(t *testing.T) {
	// Arrange
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("order:export", "导出订单", "订单管理"),
	))
	tpl := template.New(
		template.Define("ops", "运营", "desc", "user:list", "order:export"),
	)

	// Act
	_, err := rbac.New(rbac.WithDB(&gorm.DB{}), rbac.WithPermissionRegistry(reg), rbac.WithModules(tpl))

	// Assert
	require.NoError(t, err)
	require.Len(t, tpl.Templates(), 1)
	require.Empty(t, tpl.Migrations(), "代码声明形态无数据库迁移")
}

func TestModule_Name(t *testing.T) {
	require.Equal(t, "template", template.New().Name())
}
