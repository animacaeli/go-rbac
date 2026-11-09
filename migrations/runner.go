package migrations

import (
	"context"
	"database/sql"
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

// 迁移串行化：多实例（滚动发布、多副本启动）同时执行迁移时，GET_LOCK
// 保证只有一个执行者；后来者等待锁而不是重复执行 DDL。
//
// 锁名按当前数据库名隔离：MySQL 的 GET_LOCK 是**服务器级**的，若同一实例上
// 有多个库（多租户 SaaS、开发机多套库），共用锁名会让不同库的迁移互相阻塞。
const (
	migrationLockPrefix  = "rbac:migrate:"
	migrationLockTimeout = 30 // seconds
)

// migrationLockSQL 返回锁名表达式：服务器级锁 + 库名隔离，长度截断到
// MySQL 的 64 字符上限（库名本身最多 64 字符）。
const migrationLockSQL = "LEFT(CONCAT('" + migrationLockPrefix + "', COALESCE(DATABASE(), '')), 64)"

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

// Apply 执行迁移：获取迁移锁 → 确保 schema_migrations 存在 → 按计划逐条应用
// 未执行的版本。
//
// 执行约束（§5.7）：
//   - 整个流程固定在**单条数据库连接**上：GET_LOCK 与动态 DDL 使用的会话变量
//     （@has_xxx / @ddl）都是连接级状态，连接池漂移会使锁失效、PREPARE 读到空变量；
//   - 每条语句执行后立即检查错误；同一迁移的全部语句成功后才写入版本记录；
//   - 迁移 SQL 必须是可重入的（本库的迁移用 information_schema + 动态 DDL 实现
//     "对象已存在则跳过"）：MySQL DDL 隐式提交，部分失败后重跑不能依赖回滚。
func Apply(ctx context.Context, db *gorm.DB, all []Migration) error {
	plan := Plan(all)
	return db.WithContext(ctx).Connection(func(conn *gorm.DB) error {
		if err := acquireLock(conn); err != nil {
			return err
		}
		defer releaseLock(ctx, conn)

		if err := conn.Exec(schemaMigrationsDDL).Error; err != nil {
			return fmt.Errorf("rbac/migrations: create schema_migrations: %w", err)
		}
		applied, err := appliedVersions(conn)
		if err != nil {
			return err
		}
		for _, m := range plan {
			if _, ok := applied[m.ID()]; ok {
				continue
			}
			for _, stmt := range splitStatements(m.SQL) {
				if err := conn.Exec(stmt).Error; err != nil {
					return fmt.Errorf("rbac/migrations: apply %s statement failed: %w", m.ID(), err)
				}
			}
			if err := conn.Exec(
				"INSERT INTO schema_migrations (module, version, name, applied_at) VALUES (?, ?, ?, UTC_TIMESTAMP(3))",
				m.Module, m.Version, m.Name,
			).Error; err != nil {
				return fmt.Errorf("rbac/migrations: record %s: %w", m.ID(), err)
			}
		}
		return nil
	})
}

// acquireLock 获取迁移互斥锁（连接级）。超时返回错误而不是无限等待。
func acquireLock(conn *gorm.DB) error {
	var got sql.NullInt64
	row := conn.Raw("SELECT GET_LOCK("+migrationLockSQL+", ?)", migrationLockTimeout).Row()
	if row == nil {
		return fmt.Errorf("rbac/migrations: acquire lock: no result set")
	}
	if err := row.Scan(&got); err != nil {
		return fmt.Errorf("rbac/migrations: acquire lock: %w", err)
	}
	if !got.Valid || got.Int64 != 1 {
		return fmt.Errorf("rbac/migrations: another instance is running migrations (lock wait timeout)")
	}
	return nil
}

// releaseLock 释放迁移锁。使用 WithoutCancel：请求 ctx 被取消也必须释放。
//
// 用 DO（无结果集）而非 SELECT + Row()：迁移失败时连接可能带有 Statement
// 错误，Row() 会返回 nil 并在 defer 中 panic，掩盖真正的迁移错误。
// NewDB 会话避免复用失败语句的状态；错误忽略（连接关闭时 MySQL 自动释放锁）。
func releaseLock(ctx context.Context, conn *gorm.DB) {
	releaseCtx := context.WithoutCancel(ctx)
	_ = conn.Session(&gorm.Session{NewDB: true, Context: releaseCtx}).
		Exec("DO RELEASE_LOCK(" + migrationLockSQL + ")").Error
}

func appliedVersions(conn *gorm.DB) (map[string]struct{}, error) {
	var rows []appliedRecord
	if err := conn.Table("schema_migrations").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("rbac/migrations: read schema_migrations: %w", err)
	}
	out := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		out[r.Module+"/"+r.Version] = struct{}{}
	}
	return out, nil
}
