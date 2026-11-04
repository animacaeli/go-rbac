// Package repository 定义数据访问抽象。
//
// §3.4 冻结决策：Repository 接口 v1 保持内部（本包位于 internal/ 下，
// Go 语言机制强制外部不可导入实现）——公开面只保留 Authorizer /
// PermissionCache / SubjectResolver / Module 等业务真正需要实现的接口。
// App 上个别暴露本包类型的方法仅为库内模块（modules/*）装配使用。
//
// 错误约定：找不到记录时实现返回本包的 ErrRecordNotFound（而非具体 ORM 错误），
// 服务层据此映射为领域哨兵错误。
package repository

import (
	"context"
	"errors"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"

	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
)

// ErrRecordNotFound 表示目标记录不存在（由各实现统一翻译）。
var ErrRecordNotFound = errors.New("rbac: record not found")

// ErrDuplicateEntry 表示唯一键冲突（并发下的"先查后插"竞态兜底）。
// 服务层据此映射为领域哨兵错误（如 core.ErrRoleCodeExists）。
var ErrDuplicateEntry = errors.New("rbac: duplicate entry")

// DeadlockRetry 执行事务体，遇 MySQL 死锁（1213，REPEATABLE READ 间隙锁）
// 时退避重试。供 gormrepo 与 tenant 模块的幂等事务共用（内部工具，无 API 承诺）。
func DeadlockRetry(fn func() error) error {
	var err error
	for attempt := 0; attempt < deadlockRetryAttempts; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		if !isDeadlock(err) {
			return err
		}
		time.Sleep(deadlockRetryBackoff * time.Duration(attempt+1))
	}
	return err
}

const (
	deadlockRetryAttempts = 3
	deadlockRetryBackoff  = 5 * time.Millisecond
)

// isDeadlock / isDuplicateEntry：MySQL 错误码判定（driver 类型断言）。
func isDeadlock(err error) bool {
	var me *mysqlDriver.MySQLError
	return errors.As(err, &me) && me.Number == 1213
}

func isDuplicateEntry(err error) bool {
	var me *mysqlDriver.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}

// TranslateDuplicate 将唯一键冲突翻译为 ErrDuplicateEntry。
func TranslateDuplicate(err error) error {
	if isDuplicateEntry(err) {
		return ErrDuplicateEntry
	}
	return err
}

// IsDuplicate 报告 err 链上是否为唯一键冲突。
func IsDuplicate(err error) bool { return errors.Is(err, ErrDuplicateEntry) }

// IsNotFound 报告 err 链上是否为"记录不存在"。
func IsNotFound(err error) bool { return errors.Is(err, ErrRecordNotFound) }

// RoleFilter 是角色列表过滤条件。零值表示全量（分页参数仍生效）。
type RoleFilter struct {
	Code   string // 精确匹配
	Status *uint8 // 状态过滤
	Offset int
	Limit  int // <=0 时默认 100，上限 1000
}

// RoleRepo 是角色表数据访问。
type RoleRepo interface {
	Create(ctx context.Context, role *model.Role) error
	FindByID(ctx context.Context, id uint64) (*model.Role, error)
	FindByCode(ctx context.Context, code string) (*model.Role, error)
	// UpdateProfile 仅更新展示元数据（name/description），code 与 status 不可经此修改。
	UpdateProfile(ctx context.Context, id uint64, name, description string) error
	SetStatus(ctx context.Context, id uint64, status uint8) error
	// DeleteWithAssociations 在同一事务内删除角色及其关联行（§5.3）。
	// 调用方必须先完成"是否正在被使用"检查。
	DeleteWithAssociations(ctx context.Context, id uint64) error
	List(ctx context.Context, f RoleFilter) ([]model.Role, error)
	// CountUsers 统计角色关联用户数（删除前检查，§2.4）。
	CountUsers(ctx context.Context, roleID uint64) (int64, error)
}

// PermissionRepo 是权限表数据访问。
type PermissionRepo interface {
	FindByCode(ctx context.Context, code string) (*model.Permission, error)
	FindByCodes(ctx context.Context, codes []string) ([]model.Permission, error)
	ListAll(ctx context.Context) ([]model.Permission, error)
	// SetStatus 更新权限状态（启用/手动禁用；废弃状态由同步机制管理）。
	SetStatus(ctx context.Context, id uint64, status uint8) error
	// ApplySync 在单个事务内应用权限同步差量计划（registry.Diff 计算）。
	ApplySync(ctx context.Context, plan registry.SyncPlan) error
}

// UserRoleRepo 是用户角色关联表数据访问（纯关联表，撤销即物理删除，§5.3）。
type UserRoleRepo interface {
	// Assign 幂等分配角色（已存在则无操作）。
	Assign(ctx context.Context, subjectID string, roleID uint64) error
	// Revoke 回收角色，幂等（不存在则无操作）。
	Revoke(ctx context.Context, subjectID string, roleID uint64) error
	ListBySubject(ctx context.Context, subjectID string) ([]model.UserRole, error)
	// ListRolesBySubject 返回主体的角色（含被禁用角色，由服务层/聚合查询过滤）。
	ListRolesBySubject(ctx context.Context, subjectID string) ([]model.Role, error)
	// SubjectIDsOfRole 反查角色关联的用户（缓存失效 fan-out，§5.4）。
	SubjectIDsOfRole(ctx context.Context, roleID uint64) ([]string, error)
}

// RolePermissionRepo 是角色权限关联表数据访问。
type RolePermissionRepo interface {
	// SetPermissions 以差量方式将角色权限集合替换为给定集合（事务内增删）。
	SetPermissions(ctx context.Context, roleID uint64, permissionIDs []uint64) error
	PermissionIDsOfRole(ctx context.Context, roleID uint64) ([]uint64, error)
	// PermissionCodesOfRole 返回角色关联的"启用状态"权限码（授权者持权约束用）。
	PermissionCodesOfRole(ctx context.Context, roleID uint64) ([]string, error)
	// PermissionsOfRole 返回角色关联的权限记录（含禁用/废弃，展示用）。
	PermissionsOfRole(ctx context.Context, roleID uint64) ([]model.Permission, error)
}

// UserGrantRepo 是用户额外授权表数据访问（完整生命周期，§2.5）。
type UserGrantRepo interface {
	// Grant 在事务内：先撤销同 (subject_id, permission_id) 的全部未撤销行
	// （含已过期未撤销，主防线），再插入新授权。g.CreatedBy 同时作为撤销人。
	Grant(ctx context.Context, g model.UserGrant, now time.Time) error
	// Revoke 撤销当前活跃授权，返回受影响行数（0 表示本就无活跃授权）。
	Revoke(ctx context.Context, subjectID string, permissionID uint64, revokedBy string, now time.Time) (int64, error)
	// FindActive 返回未撤销的授权记录（无论是否已到期）。
	FindActive(ctx context.Context, subjectID string, permissionID uint64) (*model.UserGrant, error)
	ListBySubject(ctx context.Context, subjectID string) ([]model.UserGrant, error)
	// ListActiveBySubject 返回未撤销且未到期的授权。
	ListActiveBySubject(ctx context.Context, subjectID string, now time.Time) ([]model.UserGrant, error)
}

// AuthorizationRepo 是授权热路径的聚合查询（§5.4 索引设计服务这些 SQL）。
type AuthorizationRepo interface {
	// EffectiveRolePermissions 返回主体经"启用角色"持有的"启用权限"码集合。
	EffectiveRolePermissions(ctx context.Context, subjectID string) ([]string, error)
	// EffectiveGrantPermissions 返回主体未撤销且未到期的额外授权权限码集合
	// （权限本身必须处于启用状态）。
	EffectiveGrantPermissions(ctx context.Context, subjectID string, now time.Time) ([]string, error)
	// HasBuiltinSuperAdminRole 判定主体是否持有内置超管角色（§7.3）。
	HasBuiltinSuperAdminRole(ctx context.Context, subjectID string) (bool, error)
	// NearestGrantExpiry 返回主体最近一条未撤销授权的到期时间（永久授权不计），
	// 无到期授权时返回 nil。缓存 TTL 不得超过该时间（§6.5）。
	NearestGrantExpiry(ctx context.Context, subjectID string, now time.Time) (*time.Time, error)
}

// Repos 聚合全部数据访问实现，由 rbac.New 组装。
type Repos struct {
	Roles           RoleRepo
	Permissions     PermissionRepo
	UserRoles       UserRoleRepo
	RolePermissions RolePermissionRepo
	Grants          UserGrantRepo
	Authorization   AuthorizationRepo
}
