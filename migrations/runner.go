package migrations

import (
	"context"
	"fmt"
	"sort"

	"gorm.io/gorm"
)

// schemaMigrationsDDL 创建迁移版本表。表名不带 rbac_ 前缀（§5.7 约定）。
const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    module     VARCHAR(64)  NOT NULL,
    version    VARCHAR(32)  NOT NULL,
    name       VARCHAR(255) NOT NULL DEFAULT '',
    applied_at DATETIME(3)  NOT NULL,
    PRIMARY KEY (module, version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
`

type appliedRecord struct {
	Module  string `gorm:"column:module"`
	Version string `gorm:"column:version"`
}

func (appliedRecord) TableName() string { return "schema_migrations" }

// Plan 将迁移排序为执行计划：Core 恒在最前，其余模块按传入（注册）顺序，
// 同一模块内按版本升序。
func Plan(all []Migration) []Migration {
	core := make([]Migration, 0, len(all))
	var rest []Migration
	seen := make(map[string]struct{}, len(all))
	for _, m := range all {
		id := m.ID()
		if _, dup := seen[id]; dup {
			panic(fmt.Sprintf("rbac/migrations: duplicate migration id %s", id))
		}
		seen[id] = struct{}{}
		if m.Module == CoreModule {
			core = append(core, m)
		} else {
			rest = append(rest, m)
		}
	}
	sort.Slice(core, func(i, j int) bool { return core[i].Version < core[j].Version })
	// rest 保持模块注册顺序；模块内部多个版本仍需升序。
	byModule := make(map[string][]Migration)
	var order []string
	for _, m := range rest {
		if _, ok := byModule[m.Module]; !ok {
			order = append(order, m.Module)
		}
		byModule[m.Module] = append(byModule[m.Module], m)
	}
	plan := make([]Migration, 0, len(all))
	plan = append(plan, core...)
	for _, mod := range order {
		ms := byModule[mod]
		sort.Slice(ms, func(i, j int) bool { return ms[i].Version < ms[j].Version })
		plan = append(plan, ms...)
	}
	return plan
}

// Apply 执行迁移：确保 schema_migrations 存在，按计划逐条应用未执行的版本。
// 每个迁移内的语句逐条执行（MySQL DDL 隐式提交，无法整体回滚，§5.7），
// 全部语句成功后才写入版本记录；任一失败立即返回错误。
func Apply(ctx context.Context, db *gorm.DB, all []Migration) error {
	if err := db.WithContext(ctx).Exec(schemaMigrationsDDL).Error; err != nil {
		return fmt.Errorf("rbac/migrations: create schema_migrations: %w", err)
	}

	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return err
	}

	for _, m := range Plan(all) {
		if _, ok := applied[m.ID()]; ok {
			continue
		}
		for _, stmt := range splitStatements(m.SQL) {
			if err := db.WithContext(ctx).Exec(stmt).Error; err != nil {
				return fmt.Errorf("rbac/migrations: apply %s statement failed: %w", m.ID(), err)
			}
		}
		if err := db.WithContext(ctx).Exec(
			"INSERT INTO schema_migrations (module, version, name, applied_at) VALUES (?, ?, ?, UTC_TIMESTAMP(3))",
			m.Module, m.Version, m.Name,
		).Error; err != nil {
			return fmt.Errorf("rbac/migrations: record %s: %w", m.ID(), err)
		}
	}
	return nil
}

func appliedVersions(ctx context.Context, db *gorm.DB) (map[string]struct{}, error) {
	var rows []appliedRecord
	if err := db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("rbac/migrations: read schema_migrations: %w", err)
	}
	out := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		out[r.Module+"/"+r.Version] = struct{}{}
	}
	return out, nil
}
