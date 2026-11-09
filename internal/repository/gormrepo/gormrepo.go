// Package gormrepo 是 repository 接口的 GORM 实现（第一版默认实现，§3.2）。
//
// 实现约定：
//   - 所有写操作使用 UTC 时间（应用层统一 UTC，§5.1）
//   - 记录不存在时返回 repository.ErrRecordNotFound
//   - 幂等写入使用 ON DUPLICATE KEY / 差量更新，重复执行无害
package gormrepo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// subjectVersionKey 返回主体版本计数器的权威键。主体统一小写：库表排序规则
// 大小写不敏感，缓存键（core.canonicalSubject）也按小写规范化，三者必须一致。
func subjectVersionKey(ctx context.Context, subjectID string) string {
	return repository.TenantScope(ctx) + ":subject:" + strings.ToLower(subjectID) + ":version"
}

// resultHardLimit 是列表类查询的硬上限：防止单主体/单角色的历史数据无界
// 增长拖垮调用方（授权判定走聚合查询，不受影响）。
const resultHardLimit = 1000

// Repos 聚合 GORM 实现的全部数据访问。
type Repos struct {
	db *gorm.DB
}

// New 以给定 GORM DB 句柄构造。句柄由业务项目创建并注入（rbac.WithDB）。
func New(db *gorm.DB) *Repos { return &Repos{db: db} }

func (r *Repos) writer(ctx context.Context) *gorm.DB { return r.db.WithContext(ctx) }

// BumpCounterTx 在既有事务内递增计数器（UPSERT 自增）。
// 授权变更与版本递增同事务的权威落点（§6.2；外部审核 P0-1）。
func BumpCounterTx(tx *gorm.DB, key string) error {
	return tx.Exec(
		"INSERT INTO rbac_counters (k, v, updated_at) VALUES (?, 1, UTC_TIMESTAMP(3)) "+
			"ON DUPLICATE KEY UPDATE v = v + 1, updated_at = UTC_TIMESTAMP(3)", key,
	).Error
}

func notFoundByID(what string, id uint64) error {
	return fmt.Errorf("%w: %s id=%d", repository.ErrRecordNotFound, what, id)
}

// translateFirst 只把 gorm.ErrRecordNotFound 翻译为仓储 NotFound；连接失败、
// 超时、ctx 取消等基础设施错误原样返回（否则 503 会被伪装成 404）。
func translateFirst(err error, format string, args ...any) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("%w: "+format, append([]any{repository.ErrRecordNotFound}, args...)...)
	}
	return err
}

// ---- RoleRepo ----

type roleRepo struct{ r *Repos }

func (x roleRepo) Create(ctx context.Context, role *model.Role) error {
	return translateDuplicate(x.r.writer(ctx).Create(role).Error)
}

func (x roleRepo) FindByID(ctx context.Context, id uint64) (*model.Role, error) {
	var role model.Role
	if err := x.r.writer(ctx).First(&role, "id = ?", id).Error; err != nil {
		return nil, translateFirst(err, "role id=%d", id)
	}
	return &role, nil
}

func (x roleRepo) FindByCode(ctx context.Context, code string) (*model.Role, error) {
	var role model.Role
	if err := x.r.writer(ctx).First(&role, "code = ?", code).Error; err != nil {
		return nil, translateFirst(err, "role code=%s", code)
	}
	return &role, nil
}

func (x roleRepo) UpdateProfile(ctx context.Context, id uint64, name, description string) error {
	res := x.r.writer(ctx).
		Model(&model.Role{}).
		Where("id = ?", id).
		Updates(map[string]any{"name": name, "description": description})
	if res.Error != nil {
		return res.Error
	}
	// RowsAffected==0 既可能是"值未变化"也可能是"行已被删除"：用存在性区分。
	return x.expectExists(ctx, id, res.RowsAffected)
}

// expectExists 在受影响行数为 0 时复核角色是否存在（避免把无变化误报为成功、
// 把并发删除静默吞掉）。
func (x roleRepo) expectExists(ctx context.Context, id uint64, affected int64) error {
	if affected > 0 {
		return nil
	}
	var n int64
	if err := x.r.writer(ctx).Model(&model.Role{}).Where("id = ?", id).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return notFoundByID("role", id)
	}
	return nil
}

func (x roleRepo) SetStatus(ctx context.Context, id uint64, status uint8) error {
	// 角色级变更 → epoch 同事务递增（§6.3）。
	return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.Role{}).
			Where("id = ?", id).
			Update("status", status)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected > 0 {
			return BumpCounterTx(tx, repository.EpochKey(repository.TenantScope(ctx)))
		}
		var n int64
		if err := tx.Model(&model.Role{}).Where("id = ?", id).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return notFoundByID("role", id)
		}
		return nil
	})
}

// DeleteWithAssociations 在事务内复核未被分配后删除角色及其关联行
// （§5.3：硬删 + 同事务清理关联）。
func (x roleRepo) DeleteWithAssociations(ctx context.Context, id uint64) error {
	// 角色级变更 → epoch 同事务递增（§6.3）。
	return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
		var used int64
		if err := tx.Model(&model.UserRole{}).Where("role_id = ?", id).Count(&used).Error; err != nil {
			return err
		}
		if used > 0 {
			return fmt.Errorf("%w: %d subject(s), role id=%d", repository.ErrRoleInUse, used, id)
		}
		if err := tx.Where("role_id = ?", id).Delete(&model.UserRole{}).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", id).Delete(&model.RolePermission{}).Error; err != nil {
			return err
		}
		// datascope 是可选模块：表不存在时跳过，存在则清理孤儿数据范围行。
		if err := tx.Exec("DELETE FROM rbac_role_data_scopes WHERE role_id = ?", id).Error; err != nil && !repository.IsMissingTable(err) {
			return err
		}
		if err := BumpCounterTx(tx, repository.EpochKey(repository.TenantScope(ctx))); err != nil {
			return err
		}
		res := tx.Delete(&model.Role{}, "id = ?", id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return notFoundByID("role", id)
		}
		return nil
	})
}

func (x roleRepo) List(ctx context.Context, f repository.RoleFilter) ([]model.Role, error) {
	q := x.r.writer(ctx).Model(&model.Role{})
	if f.Code != "" {
		q = q.Where("code = ?", f.Code)
	}
	if f.Status != nil {
		q = q.Where("status = ?", *f.Status)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	var roles []model.Role
	if err := q.Order("id ASC").Offset(f.Offset).Limit(limit).Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (x roleRepo) CountUsers(ctx context.Context, roleID uint64) (int64, error) {
	var n int64
	err := x.r.writer(ctx).
		Model(&model.UserRole{}).
		Where("role_id = ?", roleID).
		Count(&n).Error
	return n, err
}

// ---- PermissionRepo ----

type permissionRepo struct{ r *Repos }

func (x permissionRepo) FindByCode(ctx context.Context, code string) (*model.Permission, error) {
	var p model.Permission
	if err := x.r.writer(ctx).First(&p, "code = ?", code).Error; err != nil {
		return nil, translateFirst(err, "permission code=%s", code)
	}
	return &p, nil
}

func (x permissionRepo) FindByCodes(ctx context.Context, codes []string) ([]model.Permission, error) {
	if len(codes) == 0 {
		return nil, nil
	}
	var perms []model.Permission
	if err := x.r.writer(ctx).Where("code IN ?", codes).Find(&perms).Error; err != nil {
		return nil, err
	}
	return perms, nil
}

func (x permissionRepo) ListAll(ctx context.Context) ([]model.Permission, error) {
	var perms []model.Permission
	if err := x.r.writer(ctx).Order("code ASC").Find(&perms).Error; err != nil {
		return nil, err
	}
	return perms, nil
}

func (x permissionRepo) SetStatus(ctx context.Context, id uint64, status uint8) error {
	// 权限表是全局定义：禁用/启用必须递增**全局** epoch（跨全部租户域）。
	return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.Permission{}).
			Where("id = ?", id).
			Update("status", status)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected > 0 {
			return BumpCounterTx(tx, repository.GlobalEpochKey)
		}
		return nil
	})
}

// ApplySync 在单个事务内应用同步差量计划（§2.3，registry.Diff 计算）。
func (x permissionRepo) ApplySync(ctx context.Context, plan registry.SyncPlan) error {
	if !plan.Changed() {
		return nil
	}
	return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
		// 权限集变化影响全部租户域：全局 epoch 同事务递增（§6.3）。
		if err := BumpCounterTx(tx, repository.GlobalEpochKey); err != nil {
			return err
		}
		for i := range plan.Inserts {
			// 幂等兜底：并发重复同步时唯一键冲突视为已插入。
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&plan.Inserts[i]).Error; err != nil {
				return err
			}
		}
		for _, p := range plan.MetadataUpdates {
			if err := tx.Model(&model.Permission{}).
				Where("id = ?", p.ID).
				Updates(map[string]any{
					"name":        p.Name,
					"module":      p.Module,
					"description": p.Description,
				}).Error; err != nil {
				return err
			}
		}
		for _, id := range plan.ReactivateIDs {
			if err := tx.Model(&model.Permission{}).
				Where("id = ? AND status = ?", id, model.PermissionStatusDeprecated).
				Update("status", model.PermissionStatusEnabled).Error; err != nil {
				return err
			}
		}
		for _, id := range plan.DeprecateIDs {
			if err := tx.Model(&model.Permission{}).
				Where("id = ? AND status = ?", id, model.PermissionStatusEnabled).
				Update("status", model.PermissionStatusDeprecated).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ---- UserRoleRepo ----

type userRoleRepo struct{ r *Repos }

func (x userRoleRepo) Assign(ctx context.Context, subjectID string, roleID uint64) error {
	return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
		inserted, err := insertUserRoles(tx, []model.UserRole{{SubjectID: subjectID, RoleID: roleID}})
		if err != nil {
			return err
		}
		if inserted > 0 {
			return BumpCounterTx(tx, subjectVersionKey(ctx, subjectID))
		}
		return nil
	})
}

// AssignMany 在一个事务内为一个主体分配多个角色；仅在有新建时递增一次版本。
func (x userRoleRepo) AssignMany(ctx context.Context, subjectID string, roleIDs []uint64) error {
	if len(roleIDs) == 0 {
		return nil
	}
	rows := make([]model.UserRole, 0, len(roleIDs))
	seen := make(map[uint64]struct{}, len(roleIDs))
	for _, id := range roleIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		rows = append(rows, model.UserRole{SubjectID: subjectID, RoleID: id})
	}
	return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
		inserted, err := insertUserRoles(tx, rows)
		if err != nil {
			return err
		}
		if inserted > 0 {
			return BumpCounterTx(tx, subjectVersionKey(ctx, subjectID))
		}
		return nil
	})
}

// AssignRoleToSubjects 在一个事务内把一个角色分配给多个主体，并为每个新建
// 成功的主体递增版本（同事务，全成或全败）。
func (x userRoleRepo) AssignRoleToSubjects(ctx context.Context, roleID uint64, subjectIDs []string) error {
	if len(subjectIDs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(subjectIDs))
	return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
		for _, sid := range subjectIDs {
			if _, dup := seen[sid]; dup {
				continue
			}
			seen[sid] = struct{}{}
			inserted, err := insertUserRoles(tx, []model.UserRole{{SubjectID: sid, RoleID: roleID}})
			if err != nil {
				return err
			}
			if inserted > 0 {
				if err := BumpCounterTx(tx, subjectVersionKey(ctx, sid)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// insertUserRoles 批量幂等插入，返回实际新建行数（MySQL 受影响行数语义：
// ON DUPLICATE KEY UPDATE 命中已存在行时为 0）。使用 RowsAffected 而非
// LastInsertId 判断是否新建——后者不是文档化的插入信号。
func insertUserRoles(tx *gorm.DB, rows []model.UserRole) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&rows)
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}

func (x userRoleRepo) Revoke(ctx context.Context, subjectID string, roleID uint64) error {
	return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Where("subject_id = ? AND role_id = ?", subjectID, roleID).
			Delete(&model.UserRole{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected > 0 {
			return BumpCounterTx(tx, subjectVersionKey(ctx, subjectID))
		}
		return nil
	})
}

func (x userRoleRepo) ListBySubject(ctx context.Context, subjectID string) ([]model.UserRole, error) {
	var urs []model.UserRole
	if err := x.r.writer(ctx).
		Where("subject_id = ?", subjectID).
		Order("id ASC").
		Limit(resultHardLimit).
		Find(&urs).Error; err != nil {
		return nil, err
	}
	return urs, nil
}

func (x userRoleRepo) ListRolesBySubject(ctx context.Context, subjectID string) ([]model.Role, error) {
	var roles []model.Role
	if err := x.r.writer(ctx).
		Joins("JOIN rbac_user_roles ur ON ur.role_id = rbac_roles.id").
		Where("ur.subject_id = ?", subjectID).
		Order("rbac_roles.id ASC").
		Limit(resultHardLimit).
		Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (x userRoleRepo) SubjectIDsOfRole(ctx context.Context, roleID uint64) ([]string, error) {
	var ids []string
	if err := x.r.writer(ctx).
		Model(&model.UserRole{}).
		Where("role_id = ?", roleID).
		Limit(resultHardLimit).
		Pluck("subject_id", &ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}

// ---- RolePermissionRepo ----

type rolePermissionRepo struct{ r *Repos }

// SetPermissions 以差量替换角色权限集合（事务内）。
func (x rolePermissionRepo) SetPermissions(ctx context.Context, roleID uint64, permissionIDs []uint64) error {
	want := make(map[uint64]struct{}, len(permissionIDs))
	rows := make([]model.RolePermission, 0, len(permissionIDs))
	for _, id := range permissionIDs {
		if _, dup := want[id]; dup {
			continue
		}
		want[id] = struct{}{}
		rows = append(rows, model.RolePermission{RoleID: roleID, PermissionID: id})
	}

	// 差量事务幂等：并发下 RR 间隙锁死锁（1213）有界重试（同 Grant）。
	// 角色级变更递增 epoch（P0-2）：一次原子失效全域，消除逐用户 fan-out 的部分成功。
	return runWithDeadlockRetry(func() error {
		return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
			var currentIDs []uint64
			if err := tx.Model(&model.RolePermission{}).
				Where("role_id = ?", roleID).
				Pluck("permission_id", &currentIDs).Error; err != nil {
				return err
			}
			removeIDs := make([]uint64, 0, len(currentIDs))
			for _, cur := range currentIDs {
				if _, keep := want[cur]; !keep {
					removeIDs = append(removeIDs, cur)
				}
			}
			if len(removeIDs) > 0 {
				if err := tx.Where("role_id = ? AND permission_id IN ?", roleID, removeIDs).
					Delete(&model.RolePermission{}).Error; err != nil {
					return err
				}
			}
			removed := len(removeIDs)
			current := make(map[uint64]struct{}, len(currentIDs))
			for _, cur := range currentIDs {
				current[cur] = struct{}{}
			}
			var add []model.RolePermission
			for _, row := range rows {
				if _, exists := current[row.PermissionID]; !exists {
					add = append(add, row)
				}
			}
			if len(add) > 0 {
				if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&add).Error; err != nil {
					return err
				}
			}
			if removed > 0 || len(add) > 0 {
				return BumpCounterTx(tx, repository.TenantScope(ctx)+":epoch")
			}
			return nil
		})
	})
}

func (x rolePermissionRepo) PermissionIDsOfRole(ctx context.Context, roleID uint64) ([]uint64, error) {
	var ids []uint64
	if err := x.r.writer(ctx).
		Model(&model.RolePermission{}).
		Where("role_id = ?", roleID).
		Pluck("permission_id", &ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}

func (x rolePermissionRepo) PermissionCodesOfRole(ctx context.Context, roleID uint64) ([]string, error) {
	var codes []string
	if err := x.r.writer(ctx).
		Table("rbac_role_permissions AS rp").
		Joins("JOIN rbac_permissions p ON p.id = rp.permission_id").
		Where("rp.role_id = ? AND p.status = ?", roleID, model.PermissionStatusEnabled).
		Pluck("p.code", &codes).Error; err != nil {
		return nil, err
	}
	return codes, nil
}

func (x rolePermissionRepo) PermissionsOfRole(ctx context.Context, roleID uint64) ([]model.Permission, error) {
	var perms []model.Permission
	if err := x.r.writer(ctx).
		Joins("JOIN rbac_role_permissions rp ON rp.permission_id = rbac_permissions.id").
		Where("rp.role_id = ?", roleID).
		Order("rbac_permissions.code ASC").
		Find(&perms).Error; err != nil {
		return nil, err
	}
	return perms, nil
}

// ---- UserGrantRepo ----

type userGrantRepo struct{ r *Repos }

// Grant 实现 §2.5 生命周期主防线：事务内先撤销冲突的未撤销行（含已过期），
// 再插入新授权。数据库生成列 + 唯一约束兜底并发漏网（§5.2/§5.3）。
func (x userGrantRepo) Grant(ctx context.Context, g model.UserGrant, now time.Time) error {
	// 相邻 subject_id 的并发授权可能触发 RR 间隙锁死锁（1213）——事务幂等，有界重试。
	return runWithDeadlockRetry(func() error {
		return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&model.UserGrant{}).
				Where("subject_id = ? AND permission_id = ? AND revoked_at IS NULL", g.SubjectID, g.PermissionID).
				Updates(map[string]any{
					"revoked_at": now,
					"revoked_by": g.CreatedBy,
				}).Error; err != nil {
				return err
			}
			g.CreatedAt = now
			if err := tx.Create(&g).Error; err != nil {
				return err
			}
			// 权威版本号与变更同事务递增（P0-1 第一阶段）。
			return BumpCounterTx(tx, subjectVersionKey(ctx, g.SubjectID))
		})
	})
}

func (x userGrantRepo) Revoke(ctx context.Context, subjectID string, permissionID uint64, revokedBy string, now time.Time) (int64, error) {
	// 单条 UPDATE 同样持有唯一索引 next-key 锁：并发授权/撤销风暴下可成为
	// 死锁受害者（CI 并发压力测试实测）。UPDATE 幂等，有界重试。
	var affected int64
	err := runWithDeadlockRetry(func() error {
		return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
			res := tx.Model(&model.UserGrant{}).
				Where("subject_id = ? AND permission_id = ? AND revoked_at IS NULL", subjectID, permissionID).
				Updates(map[string]any{
					"revoked_at": now,
					"revoked_by": revokedBy,
				})
			if res.Error != nil {
				return res.Error
			}
			affected = res.RowsAffected
			if affected > 0 {
				// 权威版本号与变更同事务递增（P0-1 第一阶段）。
				return BumpCounterTx(tx, subjectVersionKey(ctx, subjectID))
			}
			return nil
		})
	})
	return affected, err
}

func (x userGrantRepo) FindActive(ctx context.Context, subjectID string, permissionID uint64) (*model.UserGrant, error) {
	var g model.UserGrant
	if err := x.r.writer(ctx).
		First(&g, "subject_id = ? AND permission_id = ? AND revoked_at IS NULL", subjectID, permissionID).Error; err != nil {
		return nil, translateFirst(err, "active grant subject=%s permission_id=%d", subjectID, permissionID)
	}
	return &g, nil
}

func (x userGrantRepo) ListBySubject(ctx context.Context, subjectID string) ([]model.UserGrant, error) {
	var grants []model.UserGrant
	if err := x.r.writer(ctx).
		Where("subject_id = ?", subjectID).
		Order("id DESC").
		Limit(resultHardLimit).
		Find(&grants).Error; err != nil {
		return nil, err
	}
	return grants, nil
}

func (x userGrantRepo) ListActiveBySubject(ctx context.Context, subjectID string, now time.Time) ([]model.UserGrant, error) {
	var grants []model.UserGrant
	if err := x.r.writer(ctx).
		Where("subject_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", subjectID, now).
		Order("id DESC").
		Limit(resultHardLimit).
		Find(&grants).Error; err != nil {
		return nil, err
	}
	return grants, nil
}

// ---- CountersRepo ----

type countersRepo struct{ r *Repos }

func (x countersRepo) Get(ctx context.Context, key string) (int64, error) {
	var v int64
	if err := x.r.writer(ctx).
		Table("rbac_counters").
		Select("v").
		Where("k = ?", key).
		Limit(1).
		Scan(&v).Error; err != nil {
		return 0, err
	}
	return v, nil
}

func (x countersRepo) Bump(ctx context.Context, key string) error {
	return x.r.writer(ctx).Transaction(func(tx *gorm.DB) error {
		return BumpCounterTx(tx, key)
	})
}

// ---- AuthorizationRepo（热路径聚合查询，§5.4） ----

type authorizationRepo struct{ r *Repos }

func (x authorizationRepo) EffectiveRolePermissions(ctx context.Context, subjectID string) ([]string, error) {
	var codes []string
	if err := x.r.writer(ctx).
		Table("rbac_user_roles AS ur").
		Joins("JOIN rbac_roles r ON r.id = ur.role_id AND r.status = ?", model.RoleStatusEnabled).
		Joins("JOIN rbac_role_permissions rp ON rp.role_id = r.id").
		Joins("JOIN rbac_permissions p ON p.id = rp.permission_id AND p.status = ?", model.PermissionStatusEnabled).
		Where("ur.subject_id = ?", subjectID).
		Distinct().
		Pluck("p.code", &codes).Error; err != nil {
		return nil, err
	}
	return codes, nil
}

func (x authorizationRepo) EffectiveGrantPermissions(ctx context.Context, subjectID string, now time.Time) ([]string, error) {
	var codes []string
	if err := x.r.writer(ctx).
		Table("rbac_user_grants AS ug").
		Joins("JOIN rbac_permissions p ON p.id = ug.permission_id AND p.status = ?", model.PermissionStatusEnabled).
		Where("ug.subject_id = ? AND ug.revoked_at IS NULL AND (ug.expires_at IS NULL OR ug.expires_at > ?)", subjectID, now).
		Distinct().
		Pluck("p.code", &codes).Error; err != nil {
		return nil, err
	}
	return codes, nil
}

func (x authorizationRepo) HasBuiltinSuperAdminRole(ctx context.Context, subjectID string) (bool, error) {
	var n int64
	if err := x.r.writer(ctx).
		Table("rbac_user_roles AS ur").
		Joins("JOIN rbac_roles r ON r.id = ur.role_id").
		Where("ur.subject_id = ? AND r.code = ? AND r.is_builtin = ? AND r.status = ?",
			subjectID, model.BuiltinSuperAdminRoleCode, true, model.RoleStatusEnabled).
		Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

func (x authorizationRepo) NearestGrantExpiry(ctx context.Context, subjectID string, now time.Time) (*time.Time, error) {
	// MIN() 空集返回 NULL：必须用 sql.NullTime 承接——扫进 *time.Time 会产生
	// "unsupported Scan" 错误，使"无到期授权"与真实故障无法区分（§6.5 审计发现）。
	var nullTime sql.NullTime
	if err := x.r.writer(ctx).
		Table("rbac_user_grants").
		Select("MIN(expires_at)").
		Where("subject_id = ? AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at > ?", subjectID, now).
		Scan(&nullTime).Error; err != nil {
		return nil, err
	}
	if nullTime.Valid {
		return &nullTime.Time, nil
	}
	return nil, nil
}

// Assemble 返回满足 repository.Repos 的接口聚合。
func (r *Repos) Assemble() repository.Repos {
	return repository.Repos{
		Roles:           roleRepo{r},
		Permissions:     permissionRepo{r},
		UserRoles:       userRoleRepo{r},
		RolePermissions: rolePermissionRepo{r},
		Grants:          userGrantRepo{r},
		Authorization:   authorizationRepo{r},
		Counters:        countersRepo{r},
	}
}
