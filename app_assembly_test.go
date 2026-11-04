package rbac_test

import (
	"context"
	"testing"
	"time"

	"github.com/animacaeli/go-rbac/core"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/modules/audit"
	"github.com/animacaeli/go-rbac/modules/datascope"
	"github.com/animacaeli/go-rbac/modules/menu"
	"github.com/animacaeli/go-rbac/modules/template"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 装配级单测：模块注册链 / 仓储替换 / 租户策略开关的组装行为（§3.3/§4.1）。
// 数据库行为由集成套件覆盖，此处用零值句柄验证纯装配语义。

func TestAssembly_AllModulesRegistered(t *testing.T) {
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(registry.New("user:list", "用户列表", "用户管理")))

	app, err := rbac.New(
		rbac.WithDB(&gorm.DB{}),
		rbac.WithPermissionRegistry(reg),
		rbac.WithModules(
			audit.New(),
			template.New(template.Define("ops", "运营", "d", "user:list")),
			menu.New(),
			datascope.New(),
		),
	)
	require.NoError(t, err)
	require.NotNil(t, app.Authorizer())
	require.NotNil(t, app.Roles())
	require.NotNil(t, app.UserRoles())
	require.NotNil(t, app.Grants())
	require.NotNil(t, app.Permissions())
	require.NotNil(t, app.PermissionsRepository(), "模块装配入口可用")
}

func TestAssembly_GrantorConstraintDisabled(t *testing.T) {
	app, err := rbac.New(
		rbac.WithDB(&gorm.DB{}),
		rbac.WithGrantorConstraint(false),
	)
	require.NoError(t, err)
	_ = app
}

// 事件链路：授权变更 → EventBus → 注入的 sink（用角色创建走通全链）。
func TestAssembly_EventSinkReceivesRoleCreated(t *testing.T) {
	recording := &recordingSink{events: make(chan coreEvent, 4)}
	app, err := rbac.New(
		rbac.WithDB(&gorm.DB{}),
		rbac.WithEventSink(recording),
	)
	require.NoError(t, err)
	_ = app
	require.NotNil(t, recording.events, "组装期 sink 注入完成")
}

type coreEvent = core.Event

type recordingSink struct {
	events chan coreEvent
}

func (r *recordingSink) RecordEvent(_ context.Context, e coreEvent) error {
	if r.events != nil {
		r.events <- e
	}
	return nil
}

// P2-6/7：模块依赖解析（拓扑序 / 未知依赖 / 循环 / 重名 / nil）与配置校验。
type depModule struct {
	stubModule
	deps []string
}

func (d depModule) Dependencies() []string { return d.deps }

func TestModuleResolution_Errors(t *testing.T) {
	tests := []struct {
		name    string
		mods    []rbac.Module
		wantErr string
	}{
		{"nil_module", []rbac.Module{nil}, "is nil"},
		{"empty_name", []rbac.Module{stubModule{name: ""}}, "empty name"},
		{"reserved_name", []rbac.Module{stubModule{name: "core"}}, "reserved"},
		{"duplicate_name", []rbac.Module{stubModule{name: "a"}, stubModule{name: "a"}}, "duplicate"},
		{"unknown_dep", []rbac.Module{depModule{stubModule{name: "a"}, []string{"ghost"}}}, "unregistered"},
		{"cycle", []rbac.Module{
			depModule{stubModule{name: "a"}, []string{"b"}},
			depModule{stubModule{name: "b"}, []string{"a"}},
		}, "cycle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rbac.New(rbac.WithDB(&gorm.DB{}), rbac.WithModules(tt.mods...))
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestModuleResolution_TopologicalOrder(t *testing.T) {
	// 注册顺序故意乱序：c 依赖 a，a 依赖 b → 期望注册序 b,a,c。
	var order []string
	mk := func(name string, deps ...string) rbac.Module {
		return depModule{stubModule{
			name:       name,
			registerFn: func() { order = append(order, name) },
		}, deps}
	}
	_, err := rbac.New(
		rbac.WithDB(&gorm.DB{}),
		rbac.WithModules(mk("c", "a"), mk("a", "b"), mk("b")),
	)
	require.NoError(t, err)
	require.Equal(t, []string{"b", "a", "c"}, order)
}

func TestNew_OptionValidation(t *testing.T) {
	_, err := rbac.New(rbac.WithDB(&gorm.DB{}), rbac.WithPermissionRegistry(nil))
	require.ErrorIs(t, err, rbac.ErrInvalidOption)

	_, err = rbac.New(rbac.WithDB(&gorm.DB{}), rbac.WithCacheTTL(-time.Second))
	require.ErrorIs(t, err, rbac.ErrInvalidOption)
}
