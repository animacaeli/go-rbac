// Package migrations 提供版本化 SQL 迁移：io/fs embed + schema_migrations 版本表。
//
// 设计要点（§5.7）：
//   - 不将 GORM AutoMigrate 作为生产迁移方案（仅可用于开发期）。
//   - MySQL DDL 存在隐式提交，多语句迁移不是原子的，因此迁移步骤小、可重入，
//     每条语句独立执行，成功后记录版本。
//   - 迁移执行权在业务项目：app.Migrate(ctx) 只是执行器。
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed core/*.sql
var coreFS embed.FS

// CoreModule 是核心模块在迁移中的固定标识；执行顺序始终排在所有扩展模块之前（§3.3）。
const CoreModule = "core"

// Core 返回核心模块的全部迁移，按版本升序。
func Core() []Migration {
	entries, err := fs.ReadDir(coreFS, "core")
	if err != nil {
		panic(fmt.Sprintf("rbac/migrations: read embedded core migrations: %v", err))
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m, err := migrationFromFilename(e.Name())
		if err != nil {
			panic(fmt.Sprintf("rbac/migrations: %v", err))
		}
		data, err := coreFS.ReadFile("core/" + e.Name())
		if err != nil {
			panic(fmt.Sprintf("rbac/migrations: read %s: %v", e.Name(), err))
		}
		m.SQL = string(data)
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}

// migrationFromFilename 解析形如 0001_init_core.sql 的文件名。
func migrationFromFilename(name string) (Migration, error) {
	base := strings.TrimSuffix(name, ".sql")
	version, rest, found := strings.Cut(base, "_")
	if !found || version == "" || rest == "" {
		return Migration{}, fmt.Errorf("invalid migration filename %q (want NNNN_name.sql)", name)
	}
	return Migration{Module: CoreModule, Version: version, Name: rest}, nil
}
