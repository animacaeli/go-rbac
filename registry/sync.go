package registry

import (
	"context"
	"fmt"

	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/repository"
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

// Sync 将注册中心内容同步至数据库（§2.3 同步规则），幂等可重复执行：
//
//  1. 新增权限自动注册（不自动授权给任何角色）；
//  2. 已存在权限的展示元数据自动刷新，Code 永不修改；
//  3. 已废弃(status=2)的权限若重新出现在代码中则恢复启用；
//  4. 数据库中启用状态、但代码未注册的权限标记为已废弃；
//     手动禁用(status=0)的权限不被触碰（保留运营决策）；
//  5. 历史授权与角色关联不被清理（废弃权限在授权判断中自动失效）。
func Sync(ctx context.Context, reg *Registry, perms repository.PermissionRepo) (SyncResult, error) {
	var result SyncResult

	existing, err := perms.ListAll(ctx)
	if err != nil {
		return result, fmt.Errorf("rbac/registry: sync load permissions: %w", err)
	}

	byCode := make(map[string]model.Permission, len(existing))
	for _, p := range existing {
		byCode[p.Code] = p
	}

	registered := reg.All()
	sync := repository.PermissionSync{}
	seen := make(map[string]struct{}, len(registered))

	for _, def := range registered {
		seen[def.Code] = struct{}{}
		current, exists := byCode[def.Code]
		if !exists {
			sync.Inserts = append(sync.Inserts, model.Permission{
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
			sync.MetadataUpdates = append(sync.MetadataUpdates, updated)
		}
		if current.Status == model.PermissionStatusDeprecated {
			sync.ReactivateIDs = append(sync.ReactivateIDs, current.ID)
		}
	}

	for _, p := range existing {
		if _, registered := seen[p.Code]; registered {
			continue
		}
		// 仅废弃"启用中"的孤儿权限；手动禁用(0)与已废弃(2)不动。
		if p.Status == model.PermissionStatusEnabled {
			sync.DeprecateIDs = append(sync.DeprecateIDs, p.ID)
		}
	}

	if err := perms.ApplySync(ctx, sync); err != nil {
		return result, fmt.Errorf("rbac/registry: sync apply: %w", err)
	}

	result.Created = len(sync.Inserts)
	result.Updated = len(sync.MetadataUpdates)
	result.Reactivated = len(sync.ReactivateIDs)
	result.Deprecated = len(sync.DeprecateIDs)
	return result, nil
}
