package template_test

import (
	"context"
	"testing"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/modules/template"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/stretchr/testify/assert"
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

// 模板定义深拷贝：调用方后续修改传入/返回的切片不得影响已注册快照。
func TestTemplates_DeepCopy(t *testing.T) {
	codes := []string{"user:list"}
	m := template.New(template.Define("ops", "运营", "", codes...))

	codes[0] = "mutated:code"
	got := m.Templates()
	require.Len(t, got, 1)
	assert.Equal(t, []string{"user:list"}, got[0].PermissionCodes)

	got[0].PermissionCodes[0] = "mutated:returned"
	assert.Equal(t, []string{"user:list"}, m.Templates()[0].PermissionCodes)
}

func TestCreateFromTemplate_UnregisteredModuleFailsClosed(t *testing.T) {
	m := template.New(template.Define("ops", "运营", "", "user:list"))
	_, err := m.CreateFromTemplate(context.Background(), core.AuthorizationContext{SubjectID: "op"}, "ops", "role", "R")
	require.Error(t, err)
}
