package registry_test

import (
	"testing"

	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Diff 为纯函数：表驱动直测（无需仓储 mock，§3.4 依赖方向修正的收益）。
func TestDiff_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		registered []registry.PermissionDef
		existing   []model.Permission
		wantResult registry.SyncResult
		wantPlan   registry.SyncPlan
	}{
		{
			name:       "empty_both_no_change",
			registered: nil,
			existing:   nil,
		},
		{
			name: "new_code_inserted_enabled",
			registered: []registry.PermissionDef{
				{Code: "user:list", Name: "用户列表", Module: "用户管理"},
			},
			wantResult: registry.SyncResult{Created: 1},
			wantPlan: registry.SyncPlan{
				Inserts: []model.Permission{
					{Code: "user:list", Name: "用户列表", Module: "用户管理", Status: model.PermissionStatusEnabled},
				},
			},
		},
		{
			name: "metadata_change_updated",
			registered: []registry.PermissionDef{
				{Code: "user:list", Name: "新名字", Module: "用户管理2"},
			},
			existing: []model.Permission{
				{ID: 7, Code: "user:list", Name: "旧名字", Module: "用户管理", Status: model.PermissionStatusEnabled},
			},
			wantResult: registry.SyncResult{Updated: 1},
			wantPlan: registry.SyncPlan{
				MetadataUpdates: []model.Permission{
					{ID: 7, Code: "user:list", Name: "新名字", Module: "用户管理2", Status: model.PermissionStatusEnabled},
				},
			},
		},
		{
			name: "deprecated_code_reactivates",
			registered: []registry.PermissionDef{
				{Code: "user:list", Name: "用户列表", Module: "用户管理"},
			},
			existing: []model.Permission{
				{ID: 9, Code: "user:list", Name: "用户列表", Module: "用户管理", Status: model.PermissionStatusDeprecated},
			},
			wantResult: registry.SyncResult{Reactivated: 1},
			wantPlan:   registry.SyncPlan{ReactivateIDs: []uint64{9}},
		},
		{
			name: "orphan_enabled_deprecated_but_manual_off_untouched",
			registered: []registry.PermissionDef{
				{Code: "user:list", Name: "用户列表", Module: "用户管理"},
			},
			existing: []model.Permission{
				{ID: 3, Code: "legacy:action", Name: "遗留", Module: "legacy", Status: model.PermissionStatusEnabled},
				{ID: 4, Code: "manual:off", Name: "手动禁用", Module: "manual", Status: model.PermissionStatusDisabled},
				{ID: 5, Code: "old:gone", Name: "已废弃", Module: "old", Status: model.PermissionStatusDeprecated},
			},
			wantResult: registry.SyncResult{Created: 1, Deprecated: 1},
			wantPlan: registry.SyncPlan{
				Inserts: []model.Permission{
					{Code: "user:list", Name: "用户列表", Module: "用户管理", Status: model.PermissionStatusEnabled},
				},
				DeprecateIDs: []uint64{3},
			},
		},
		{
			name: "idempotent_rerun_no_diff",
			registered: []registry.PermissionDef{
				{Code: "user:list", Name: "用户列表", Module: "用户管理"},
			},
			existing: []model.Permission{
				{ID: 1, Code: "user:list", Name: "用户列表", Module: "用户管理", Status: model.PermissionStatusEnabled},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := registry.NewRegistry()
			require.NoError(t, reg.Register(tt.registered...))

			result, plan := registry.Diff(reg, tt.existing)

			assert.Equal(t, tt.wantResult, result)
			assert.Equal(t, tt.wantPlan, plan)
			assert.Equal(t, tt.wantResult.Changed(), plan.Changed())
		})
	}
}

// 大小写冲突：库表排序规则大小写不敏感，唯一键会命中旧行，而精确匹配认为
// 该 code 不存在——必须显式报告而不是静默"插入失败 + 废弃"。
func TestDiff_CaseConflict_Reported(t *testing.T) {
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(registry.New("order:read", "查看订单", "订单")))

	result, _ := registry.Diff(reg, []model.Permission{
		{ID: 1, Code: "Order:Read", Name: "查看订单", Module: "订单", Status: model.PermissionStatusEnabled},
	})

	require.Len(t, result.Conflicts, 1)
	assert.Contains(t, result.Conflicts[0], "Order:Read")
}
