// Package model 定义 go-rbac 的基础数据模型（GORM），对应设计文档 §5 冻结稿的五张核心表。
//
// 约定（§5.1）：
//   - 主键 BIGINT UNSIGNED AUTO_INCREMENT（Go 侧 uint64）
//   - 时间 DATETIME(3)，应用层统一 UTC
//   - 全库无 deleted_at：管理对象用 status，关联关系物理删除
//   - 表前缀固定 rbac_，v1 无 tenant_id
//
// 生产 DDL 由 migrations/ 下的版本化 SQL 提供，且**只能**由它提供：生成列
// （rbac_user_grants.active_flag）与包含生成列的部分唯一约束无法用 GORM tag
// 表达，AutoMigrate 生成的表会缺少并发兜底约束。本包 tag 仅用于运行时字段
// 映射与查询构造；擅自对生产库执行 AutoMigrate 会得到与迁移脚本不一致的表。
package model

import "time"

// 角色状态（rbac_roles.status）。
const (
	RoleStatusDisabled uint8 = 0
	RoleStatusEnabled  uint8 = 1
)

// 权限状态（rbac_permissions.status）。
const (
	PermissionStatusDisabled   uint8 = 0 // 手动禁用
	PermissionStatusEnabled    uint8 = 1 // 启用
	PermissionStatusDeprecated uint8 = 2 // 已废弃（代码中不再注册）
)

// BuiltinSuperAdminRoleCode 是内置超级管理员载体角色的 code（§7.3）。
// 该角色仅能通过初始化种子创建，管理接口不可授予、撤销、删除、禁用。
const BuiltinSuperAdminRoleCode = "super_admin"

// 字段长度约束（与 §5.2 DDL 保持一致）。
const (
	SubjectIDMaxLength = 128
	RoleCodeMaxLength  = 64
	PermCodeMaxLength  = 128
	NameMaxLength      = 128
	DescMaxLength      = 255
)

// Role 对应表 rbac_roles。
type Role struct {
	ID          uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	Code        string    `gorm:"column:code;size:64;uniqueIndex:uk_code;not null"`
	Name        string    `gorm:"column:name;size:128;not null"`
	Description string    `gorm:"column:description;size:255;not null;default:''"`
	IsBuiltin   bool      `gorm:"column:is_builtin;not null;default:0"`
	Status      uint8     `gorm:"column:status;not null;default:1"`
	CreatedAt   time.Time `gorm:"column:created_at;autoCreateTime:milli"`
	UpdatedAt   time.Time `gorm:"column:updated_at;autoUpdateTime:milli"`
}

// TableName 返回表名。
func (Role) TableName() string { return "rbac_roles" }

// Permission 对应表 rbac_permissions。
type Permission struct {
	ID          uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	Code        string    `gorm:"column:code;size:128;uniqueIndex:uk_code;not null"`
	Name        string    `gorm:"column:name;size:128;not null"`
	Module      string    `gorm:"column:module;size:64;index:idx_module;not null"`
	Description string    `gorm:"column:description;size:255;not null;default:''"`
	Status      uint8     `gorm:"column:status;not null;default:1"`
	CreatedAt   time.Time `gorm:"column:created_at;autoCreateTime:milli"`
	UpdatedAt   time.Time `gorm:"column:updated_at;autoUpdateTime:milli"`
}

// TableName 返回表名。
func (Permission) TableName() string { return "rbac_permissions" }

// UserRole 对应表 rbac_user_roles：纯关联表，撤销即物理删除，
// 历史由 Audit 模块负责（Phase 2）。
type UserRole struct {
	ID        uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	SubjectID string    `gorm:"column:subject_id;size:128;not null;uniqueIndex:uk_subject_role,priority:1"`
	RoleID    uint64    `gorm:"column:role_id;not null;uniqueIndex:uk_subject_role,priority:2;index:idx_role"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime:milli"`
}

// TableName 返回表名。
func (UserRole) TableName() string { return "rbac_user_roles" }

// RolePermission 对应表 rbac_role_permissions：纯关联表，撤销即物理删除。
type RolePermission struct {
	ID           uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	RoleID       uint64    `gorm:"column:role_id;not null;uniqueIndex:uk_role_permission,priority:1"`
	PermissionID uint64    `gorm:"column:permission_id;not null;uniqueIndex:uk_role_permission,priority:2;index:idx_permission"`
	CreatedAt    time.Time `gorm:"column:created_at;autoCreateTime:milli"`
}

// TableName 返回表名。
func (RolePermission) TableName() string { return "rbac_role_permissions" }

// UserGrant 对应表 rbac_user_grants：唯一保留完整生命周期的表，
// 撤销/过期记录不删除，服务审计（§2.5、§5.3）。
type UserGrant struct {
	ID           uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	SubjectID    string     `gorm:"column:subject_id;size:128;not null"`
	PermissionID uint64     `gorm:"column:permission_id;not null;index:idx_permission"`
	ExpiresAt    *time.Time `gorm:"column:expires_at"` // NULL=永久；缓存 TTL 不得超过最近到期时间
	Reason       string     `gorm:"column:reason;size:255;not null;default:''"`
	CreatedBy    string     `gorm:"column:created_by;size:128;not null"`
	CreatedAt    time.Time  `gorm:"column:created_at;autoCreateTime:milli"`
	RevokedAt    *time.Time `gorm:"column:revoked_at"`
	RevokedBy    *string    `gorm:"column:revoked_by;size:128"`
	// ActiveFlag 是 MySQL 生成列（IF(revoked_at IS NULL, 1, NULL) STORED），
	// 只读、由数据库生成，GORM 中标记为只读（->）。§5.3：它是兜底不是主防线。
	ActiveFlag *int8 `gorm:"column:active_flag;->"`
}

// TableName 返回表名。
func (UserGrant) TableName() string { return "rbac_user_grants" }
