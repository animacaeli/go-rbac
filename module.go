package rbac

import "github.com/animacaeli/go-rbac/migrations"

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

	// Register 向 App 注册模块自己的 Service / 扩展点，并检查模块依赖。
	// 任何错误都会使 rbac.New 失败（fail fast）。
	Register(app *App) error

	// Migrations 返回模块贡献的数据库迁移（按 Core → 模块注册顺序执行）。
	Migrations() []Migration
}
