package registry

import (
	"github.com/animacaeli/go-rbac/model"
)

// SyncResult 汇报一次权限同步的差量结果。
type SyncResult struct {
	// Created 新注册入库的权限数。
	Created int
	// Updated 元数据（name/module/description）被刷新的权限数。
	Updated int
	// Reactivated 从"已废弃"恢复为"启用"的权限数（代码重新注册）。
	Reactivated int
	// Deprecated 被标记为"已废弃"的权限数（数据库存在但代码不再注册）。
	Deprecated int
}

// Changed 报告本次同步是否产生任何差量。
func (r SyncResult) Changed() bool {
	return r.Created+r.Updated+r.Reactivated+r.Deprecated > 0
}

// SyncPlan 是权限同步的差量计划（纯数据）：由 Diff 依据注册中心与数据库
// 现状计算，由仓储层在单个事务内应用。计划与执行分离使 Diff 可纯函数测试，
// 且 registry 不依赖任何存储接口（§3.4：存储细节归属 repository）。
type SyncPlan struct {
	// Inserts 新增权限（代码新注册），status = 启用。
	Inserts []model.Permission
	// MetadataUpdates 已存在权限的展示元数据更新（name/module/description）。
	MetadataUpdates []model.Permission
	// ReactivateIDs 从"已废弃"恢复为"启用"的权限 ID（代码重新注册）。
	ReactivateIDs []uint64
	// DeprecateIDs 从"启用"标记为"已废弃"的权限 ID（代码不再注册，§2.3 规则 5/6）。
	// 手动禁用（status=0）的权限不被触碰。
	DeprecateIDs []uint64
}

// Changed 报告计划是否包含任何变更。
func (p SyncPlan) Changed() bool {
	return len(p.Inserts)+len(p.MetadataUpdates)+len(p.ReactivateIDs)+len(p.DeprecateIDs) > 0
}

// Diff 计算注册中心与数据库现状的同步差量（§2.3 同步规则），纯函数、幂等：
//
//  1. 新增权限自动注册（不自动授权给任何角色）；
//  2. 已存在权限的展示元数据自动刷新，Code 永不修改；
//  3. 已废弃(status=2)的权限若重新出现在代码中则恢复启用；
//  4. 数据库中启用状态、但代码未注册的权限标记为已废弃；
//     手动禁用(status=0)的权限不被触碰（保留运营决策）；
//  5. 历史授权与角色关联不被清理（废弃权限在授权判断中自动失效）。
func Diff(reg *Registry, existing []model.Permission) (SyncResult, SyncPlan) {
	byCode := make(map[string]model.Permission, len(existing))
	for _, p := range existing {
		byCode[p.Code] = p
	}

	registered := reg.All()
	plan := SyncPlan{}
	seen := make(map[string]struct{}, len(registered))

	for _, def := range registered {
		seen[def.Code] = struct{}{}
		current, exists := byCode[def.Code]
		if !exists {
			plan.Inserts = append(plan.Inserts, model.Permission{
				Code:        def.Code,
				Name:        def.Name,
				Module:      def.Module,
				Description: def.Description,
				Status:      model.PermissionStatusEnabled,
			})
			continue
		}
		if current.Name != def.Name || current.Module != def.Module || current.Description != def.Description {
			updated := current
			updated.Name = def.Name
			updated.Module = def.Module
			updated.Description = def.Description
			plan.MetadataUpdates = append(plan.MetadataUpdates, updated)
		}
		if current.Status == model.PermissionStatusDeprecated {
			plan.ReactivateIDs = append(plan.ReactivateIDs, current.ID)
		}
	}

	for _, p := range existing {
		if _, registered := seen[p.Code]; registered {
			continue
		}
		// 仅废弃"启用中"的孤儿权限；手动禁用(0)与已废弃(2)不动。
		if p.Status == model.PermissionStatusEnabled {
			plan.DeprecateIDs = append(plan.DeprecateIDs, p.ID)
		}
	}

	result := SyncResult{
		Created:     len(plan.Inserts),
		Updated:     len(plan.MetadataUpdates),
		Reactivated: len(plan.ReactivateIDs),
		Deprecated:  len(plan.DeprecateIDs),
	}
	return result, plan
}
