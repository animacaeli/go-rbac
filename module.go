package rbac

import (
	"fmt"

	"github.com/animacaeli/go-rbac/migrations"
)

// Migration 是版本化迁移单元（§5.7）。
type Migration = migrations.Migration

// Module 是扩展模块接入契约（§3.3 Module Registry）。
//
// 约束：
//   - Register 只做注册与收集，不做数据库操作，保证 New() 无副作用
//   - 模块之间不直接互相依赖（需要租户信息时通过 Core 的 AuthorizationContext）
//   - Module Registry 只做"模块注册 + 依赖检查 + 迁移收集"，
//     不做依赖注入容器
type Module interface {
	// Name 返回模块唯一标识（同时作为迁移 Module 键，不得为 "core"）。
	Name() string

	// Dependencies 声明依赖的模块名（按 Name 引用）。Registry 负责：
	// 依赖存在性检查、循环依赖检测，并按依赖拓扑序执行注册与迁移——
	// 业务项目无需关心传入顺序（如 tenant 替换仓储后其他模块才注册）。
	Dependencies() []string

	// Register 向 App 注册模块自己的 Service / 扩展点，并检查模块依赖。
	// 任何错误都会使 rbac.New 失败（fail fast）。
	Register(app *App) error

	// Migrations 返回模块贡献的数据库迁移（按 Core → 依赖拓扑序执行）。
	Migrations() []Migration
}

// resolveModules 校验并按依赖拓扑序排列模块。
// 校验：非 nil、名称非空且唯一、不占用保留名 "core"、依赖声明存在、无循环。
// 拓扑序在满足依赖的前提下保持注册顺序稳定。
func resolveModules(mods []Module) ([]Module, error) {
	byName := make(map[string]Module, len(mods))
	for i, mod := range mods {
		if mod == nil {
			return nil, fmt.Errorf("rbac: module at index %d is nil", i)
		}
		name := mod.Name()
		if name == "" {
			return nil, fmt.Errorf("rbac: module at index %d has empty name", i)
		}
		if name == migrations.CoreModule {
			return nil, fmt.Errorf("rbac: module name %q is reserved", name)
		}
		if _, dup := byName[name]; dup {
			return nil, fmt.Errorf("rbac: duplicate module name %q", name)
		}
		byName[name] = mod
	}
	for _, mod := range mods {
		for _, dep := range mod.Dependencies() {
			if _, ok := byName[dep]; !ok {
				return nil, fmt.Errorf("rbac: module %s depends on unregistered module %q", mod.Name(), dep)
			}
		}
	}

	// Kahn 拓扑排序（稳定：同级按注册顺序）。
	orderIdx := make(map[string]int, len(mods))
	for i, mod := range mods {
		orderIdx[mod.Name()] = i
	}
	indeg := make(map[string]int, len(mods))
	dependents := make(map[string][]Module, len(mods))
	for _, mod := range mods {
		deps := mod.Dependencies()
		seen := make(map[string]struct{}, len(deps))
		for _, d := range deps {
			if _, dup := seen[d]; dup {
				continue // 重复声明同一依赖按一次计
			}
			seen[d] = struct{}{}
			indeg[mod.Name()]++
			dependents[d] = append(dependents[d], mod)
		}
	}
	queue := make([]Module, 0, len(mods))
	for _, mod := range mods {
		if indeg[mod.Name()] == 0 {
			queue = append(queue, mod)
		}
	}
	var sorted []Module
	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]
		sorted = append(sorted, m)
		for _, next := range dependents[m.Name()] {
			indeg[next.Name()]--
			if indeg[next.Name()] == 0 {
				// 插入排序位置以保持注册顺序稳定。
				pos := len(queue)
				for i, q := range queue {
					if orderIdx[next.Name()] < orderIdx[q.Name()] {
						pos = i
						break
					}
				}
				queue = append(queue, nil)
				copy(queue[pos+1:], queue[pos:])
				queue[pos] = next
			}
		}
	}
	if len(sorted) != len(mods) {
		return nil, fmt.Errorf("rbac: module dependency cycle detected among %d modules", len(mods)-len(sorted))
	}
	return sorted, nil
}
