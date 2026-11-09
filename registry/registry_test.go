package registry_test

import (
	"testing"

	"github.com/animacaeli/go-rbac/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCode_ValidCodes_Accepted(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{"module_action", "user:list"},
		{"three_segments_builtin", "rbac:role:list"},
		{"digits_and_underscores", "order_2:export_v2"},
		{"single_char_segments", "a:b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			err := registry.ValidateCode(tt.code)

			// Assert
			require.NoError(t, err)
		})
	}
}

func TestValidateCode_InvalidCodes_Rejected(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{"empty", ""},
		{"no_colon", "userlist"},
		{"trailing_colon", "user:"},
		{"leading_colon", ":list"},
		{"empty_middle_segment", "user::list"},
		{"wildcard_star", "user:*"},
		{"wildcard_prefix", "*:list"},
		{"uppercase", "User:list"},
		{"space", "us er:list"},
		{"hyphen", "user-role:list"},
		{"chinese", "用户:列表"},
		{"too_long", "a:" + repeat("b", 128)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			err := registry.ValidateCode(tt.code)

			// Assert
			require.ErrorIs(t, err, registry.ErrInvalidPermissionCode)
		})
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestRegistry_Register_IdenticalDefinition_Idempotent(t *testing.T) {
	// Arrange
	reg := registry.NewRegistry()
	def := registry.New("user:list", "用户列表", "用户管理")

	// Act
	err1 := reg.Register(def)
	err2 := reg.Register(def)

	// Assert
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.True(t, reg.Has("user:list"))
}

func TestRegistry_Register_ConflictingDefinition_Rejected(t *testing.T) {
	// Arrange
	reg := registry.NewRegistry()

	// Act
	err1 := reg.Register(registry.New("user:list", "用户列表", "用户管理"))
	err2 := reg.Register(registry.New("user:list", "另一个名字", "用户管理"))

	// Assert
	require.NoError(t, err1)
	require.ErrorIs(t, err2, registry.ErrDuplicateRegistration)
}

func TestRegistry_Register_InvalidMetadata_Rejected(t *testing.T) {
	tests := []struct {
		name string
		def  registry.PermissionDef
	}{
		{"empty_name", registry.New("user:list", "", "用户管理")},
		{"empty_module", registry.New("user:list", "用户列表", "")},
		{"invalid_code", registry.New("user:*", "用户列表", "用户管理")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			reg := registry.NewRegistry()

			// Act
			err := reg.Register(tt.def)

			// Assert
			require.Error(t, err)
			assert.False(t, reg.Has(tt.def.Code))
		})
	}
}

func TestRegistry_All_SortedByCode(t *testing.T) {
	// Arrange
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("order:export", "导出订单", "订单管理"),
		registry.New("rbac:role:list", "角色查询", "rbac"),
	))

	// Act
	codes := reg.Codes()

	// Assert
	assert.Equal(t, []string{"order:export", "rbac:role:list", "user:list"}, codes)
}

func TestBuiltinPermissions_AllValidAndUnique(t *testing.T) {
	// Arrange
	builtin := registry.BuiltinPermissions()
	seen := make(map[string]struct{}, len(builtin))

	// Act + Assert
	require.NotEmpty(t, builtin)
	for _, def := range builtin {
		require.NoErrorf(t, registry.ValidateCode(def.Code), "builtin code %s must be valid", def.Code)
		require.NotEmptyf(t, def.Name, "builtin %s must have a name", def.Code)
		require.NotEmptyf(t, def.Module, "builtin %s must have a module", def.Code)
		_, dup := seen[def.Code]
		require.Falsef(t, dup, "builtin code %s duplicated", def.Code)
		seen[def.Code] = struct{}{}
	}
	// §4.7 内置权限码全清单。
	for _, code := range []string{
		"rbac:role:list", "rbac:role:create", "rbac:role:update", "rbac:role:delete",
		"rbac:role:assign", "rbac:user:assign_role", "rbac:grant:create",
		"rbac:grant:revoke", "rbac:permission:sync", "rbac:audit:read",
	} {
		assert.Contains(t, seen, code)
	}
}

// 批量注册是原子的：批内任一非法定义都不得留下已注册的部分。
func TestRegister_BatchFailureIsAtomic(t *testing.T) {
	reg := registry.NewRegistry()

	err := reg.Register(
		registry.New("user:list", "用户列表", "用户"),
		registry.New("invalid code", "非法", "用户"),
	)

	require.Error(t, err)
	assert.False(t, reg.Has("user:list"), "失败的批量注册不得留下部分定义")
}

// 冲突的重复定义不注册新条目（幂等相同定义除外）。
func TestRegister_ConflictingDefinitionRejected(t *testing.T) {
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(registry.New("user:list", "用户列表", "用户")))

	err := reg.Register(registry.New("user:list", "另一个名字", "用户"))

	require.ErrorIs(t, err, registry.ErrDuplicateRegistration)
	def, ok := reg.Get("user:list")
	require.True(t, ok)
	assert.Equal(t, "用户列表", def.Name, "原定义不得被覆盖")
}
