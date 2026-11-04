package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/model"
	mysqlDriver "github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

// Repos 提供租户隔离的数据访问：三张租户归属表（rbac_roles /
// rbac_user_roles / rbac_user_grants）的读写按 ctx 租户过滤；
// 权限表与角色权限表为全局定义，透传基座实现。
//
// 租户来源：ctx 中的租户槽位（core.ContextWithTenant）。缺失即 fail closed。
type Repos struct {
	base repository.Repos
	db   *gorm.DB
}

// newRepos 以基座仓储构造租户隔离仓储。
func newRepos(base repository.Repos, db *gorm.DB) *Repos {
	return &Repos{base: base, db: db}
}

// Assemble 返回满足 repository.Repos 的接口聚合。
func (r *Repos) Assemble() repository.Repos {
	return repository.Repos{
		Roles:           roleRepo{r},
		Permissions:     r.base.Permissions,
		UserRoles:       userRoleRepo{r},
		RolePermissions: r.base.RolePermissions,
		Grants:          grantRepo{r},
		Authorization:   authzRepo{r},
	}
}

func (r *Repos) writer(ctx context.Context) (*gorm.DB, string, error) {
	tenantID, ok := core.TenantFromContext(ctx)
	if !ok {
		return nil, "", errScopeMissing
	}
	return r.db.WithContext(ctx), tenantID, nil
}

func nowUTC() time.Time { return time.Now().UTC() }

// runWithDeadlockRetry：MySQL 1213（RR 间隙锁死锁）有界重试；事务幂等。
const (
	deadlockRetryAttempts = 3
	deadlockBaseBackoff   = 5 * time.Millisecond
)

func runWithDeadlockRetry(fn func() error) error {
	var err error
	for attempt := 0; attempt < deadlockRetryAttempts; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		var me *mysqlDriver.MySQLError
		if !errors.As(err, &me) || me.Number != 1213 {
			return err
		}
		time.Sleep(deadlockBaseBackoff * time.Duration(attempt+1))
	}
	return err
}

// ---- RoleRepo ----

type roleRepo struct{ r *Repos }

func (x roleRepo) Create(ctx context.Context, role *model.Role) error {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return err
	}
	if err := db.Table("rbac_roles").Create(map[string]any{
		"tenant_id":   t,
		"code":        role.Code,
		"name":        role.Name,
		"description": role.Description,
		"is_builtin":  role.IsBuiltin,
		"status":      role.Status,
		"created_at":  nowUTC(),
		"updated_at":  nowUTC(),
	}).Error; err != nil {
		var me *mysqlDriver.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			return repository.ErrDuplicateEntry
		}
		return err
	}
	// 回读填充模型字段（含 ID）。
	created, err := x.FindByCode(ctx, role.Code)
	if err != nil {
		return err
	}
	*role = *created
	return nil
}

func (x roleRepo) FindByID(ctx context.Context, id uint64) (*model.Role, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	var role model.Role
	if err := db.Table("rbac_roles").Where("id = ? AND tenant_id = ?", id, t).First(&role).Error; err != nil {
		return nil, fmt.Errorf("%w: role id=%d tenant=%s", repository.ErrRecordNotFound, id, t)
	}
	return &role, nil
}

func (x roleRepo) FindByCode(ctx context.Context, code string) (*model.Role, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	var role model.Role
	if err := db.Table("rbac_roles").Where("code = ? AND tenant_id = ?", code, t).First(&role).Error; err != nil {
		return nil, fmt.Errorf("%w: role code=%s tenant=%s", repository.ErrRecordNotFound, code, t)
	}
	return &role, nil
}

func (x roleRepo) UpdateProfile(ctx context.Context, id uint64, name, description string) error {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return err
	}
	return db.Model(&model.Role{}).
		Where("id = ? AND tenant_id = ?", id, t).
		Updates(map[string]any{"name": name, "description": description}).Error
}

func (x roleRepo) SetStatus(ctx context.Context, id uint64, status uint8) error {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return err
	}
	return db.Model(&model.Role{}).
		Where("id = ? AND tenant_id = ?", id, t).
		Update("status", status).Error
}

func (x roleRepo) DeleteWithAssociations(ctx context.Context, id uint64) error {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Table("rbac_user_roles").
			Where("role_id = ? AND tenant_id = ?", id, t).
			Delete(nil).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", id).Delete(&model.RolePermission{}).Error; err != nil {
			return err
		}
		res := tx.Table("rbac_roles").Where("id = ? AND tenant_id = ?", id, t).Delete(nil)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("%w: role id=%d tenant=%s", repository.ErrRecordNotFound, id, t)
		}
		return nil
	})
}

func (x roleRepo) List(ctx context.Context, f repository.RoleFilter) ([]model.Role, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	q := db.Table("rbac_roles").Where("tenant_id = ?", t)
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
	if err := q.Order("id ASC").Offset(f.Offset).Limit(limit).Scan(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (x roleRepo) CountUsers(ctx context.Context, roleID uint64) (int64, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return 0, err
	}
	var n int64
	if err := db.Table("rbac_user_roles").
		Where("role_id = ? AND tenant_id = ?", roleID, t).
		Count(&n).Error; err != nil {
		return 0, err
	}
	return n, nil
}

// ---- UserRoleRepo ----

type userRoleRepo struct{ r *Repos }

// roleTenantOf 校验角色归属域；不存在或跨域引用返回错误（§2.9 跨租户授权保护）。
func (x userRoleRepo) roleTenantOf(db *gorm.DB, roleID uint64, expect string) error {
	var row struct{ TenantID string }
	if err := db.Session(&gorm.Session{NewDB: true}).
		Table("rbac_roles").
		Select("tenant_id").
		Where("id = ?", roleID).
		Limit(1).
		Scan(&row).Error; err != nil {
		return err
	}
	if row.TenantID == "" && expect != "" {
		// Scan 零值无法区分"无匹配行"与"平台域角色"：以新会话计数确认。
		var exists int64
		if err := db.Session(&gorm.Session{NewDB: true}).
			Table("rbac_roles").
			Where("id = ?", roleID).
			Count(&exists).Error; err != nil {
			return err
		}
		if exists == 0 {
			return fmt.Errorf("%w: role id=%d", repository.ErrRecordNotFound, roleID)
		}
		// 存在且 tenant_id=''：平台域角色——按跨域规则在下方拒绝（除非本域即平台域）。
	}
	if row.TenantID != expect {
		return fmt.Errorf("rbac/modules/tenant: cross-tenant role reference rejected: role %d belongs to %q, scope is %q", roleID, row.TenantID, expect)
	}
	return nil
}

func (x userRoleRepo) Assign(ctx context.Context, subjectID string, roleID uint64) error {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return err
	}
	if err := x.roleTenantOf(db, roleID, t); err != nil {
		return err
	}
	// INSERT IGNORE：唯一键 (tenant_id, subject_id, role_id) 下的幂等分配
	//（map 式 Create 无法配 OnConflict 子句，MySQL 原生语义更直接）。
	return db.Exec(
		"INSERT IGNORE INTO rbac_user_roles (tenant_id, subject_id, role_id, created_at) VALUES (?, ?, ?, ?)",
		t, subjectID, roleID, nowUTC(),
	).Error
}

func (x userRoleRepo) Revoke(ctx context.Context, subjectID string, roleID uint64) error {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return err
	}
	return db.Table("rbac_user_roles").
		Where("subject_id = ? AND role_id = ? AND tenant_id = ?", subjectID, roleID, t).
		Delete(nil).Error
}

func (x userRoleRepo) ListBySubject(ctx context.Context, subjectID string) ([]model.UserRole, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	var urs []model.UserRole
	if err := db.Table("rbac_user_roles").
		Where("subject_id = ? AND tenant_id = ?", subjectID, t).
		Order("id ASC").
		Scan(&urs).Error; err != nil {
		return nil, err
	}
	return urs, nil
}

func (x userRoleRepo) ListRolesBySubject(ctx context.Context, subjectID string) ([]model.Role, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	var roles []model.Role
	if err := db.Table("rbac_roles AS r").
		Joins("JOIN rbac_user_roles ur ON ur.role_id = r.id AND ur.tenant_id = ? AND r.tenant_id = ur.tenant_id", t).
		Where("ur.subject_id = ?", subjectID).
		Order("r.id ASC").
		Scan(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

func (x userRoleRepo) SubjectIDsOfRole(ctx context.Context, roleID uint64) ([]string, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	var ids []string
	if err := db.Table("rbac_user_roles").
		Where("role_id = ? AND tenant_id = ?", roleID, t).
		Pluck("subject_id", &ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}

// ---- UserGrantRepo ----

type grantRepo struct{ r *Repos }

// Grant 落库（§2.5 主防线）：事务内先撤销本域内冲突的未撤销行，再插入。
func (x grantRepo) Grant(ctx context.Context, g model.UserGrant, now time.Time) error {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return err
	}
	// 相邻 subject_id 的并发授权可能触发 RR 间隙锁死锁（1213）——事务幂等，有界重试。
	return runWithDeadlockRetry(func() error {
		return db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Table("rbac_user_grants").
				Where("tenant_id = ? AND subject_id = ? AND permission_id = ? AND revoked_at IS NULL", t, g.SubjectID, g.PermissionID).
				Updates(map[string]any{"revoked_at": now, "revoked_by": g.CreatedBy}).Error; err != nil {
				return err
			}
			return tx.Table("rbac_user_grants").Create(map[string]any{
				"tenant_id":     t,
				"subject_id":    g.SubjectID,
				"permission_id": g.PermissionID,
				"expires_at":    g.ExpiresAt,
				"reason":        g.Reason,
				"created_by":    g.CreatedBy,
				"created_at":    now,
			}).Error
		})
	})
}

func (x grantRepo) Revoke(ctx context.Context, subjectID string, permissionID uint64, revokedBy string, now time.Time) (int64, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return 0, err
	}
	res := db.Table("rbac_user_grants").
		Where("tenant_id = ? AND subject_id = ? AND permission_id = ? AND revoked_at IS NULL", t, subjectID, permissionID).
		Updates(map[string]any{"revoked_at": now, "revoked_by": revokedBy})
	return res.RowsAffected, res.Error
}

func (x grantRepo) FindActive(ctx context.Context, subjectID string, permissionID uint64) (*model.UserGrant, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	var g model.UserGrant
	if err := db.Table("rbac_user_grants").
		Where("tenant_id = ? AND subject_id = ? AND permission_id = ? AND revoked_at IS NULL", t, subjectID, permissionID).
		First(&g).Error; err != nil {
		return nil, fmt.Errorf("%w: active grant tenant=%s subject=%s permission_id=%d", repository.ErrRecordNotFound, t, subjectID, permissionID)
	}
	return &g, nil
}

func (x grantRepo) ListBySubject(ctx context.Context, subjectID string) ([]model.UserGrant, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	var gs []model.UserGrant
	if err := db.Table("rbac_user_grants").
		Where("tenant_id = ? AND subject_id = ?", t, subjectID).
		Order("id DESC").
		Scan(&gs).Error; err != nil {
		return nil, err
	}
	return gs, nil
}

func (x grantRepo) ListActiveBySubject(ctx context.Context, subjectID string, now time.Time) ([]model.UserGrant, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	var gs []model.UserGrant
	if err := db.Table("rbac_user_grants").
		Where("tenant_id = ? AND subject_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", t, subjectID, now).
		Order("id DESC").
		Scan(&gs).Error; err != nil {
		return nil, err
	}
	return gs, nil
}

// ---- AuthorizationRepo（热路径聚合，§5.4） ----

type authzRepo struct{ r *Repos }

func (x authzRepo) EffectiveRolePermissions(ctx context.Context, subjectID string) ([]string, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	var codes []string
	if err := db.Table("rbac_user_roles AS ur").
		Joins("JOIN rbac_roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id AND r.status = ?", model.RoleStatusEnabled).
		Joins("JOIN rbac_role_permissions rp ON rp.role_id = r.id").
		Joins("JOIN rbac_permissions p ON p.id = rp.permission_id AND p.status = ?", model.PermissionStatusEnabled).
		Where("ur.subject_id = ? AND ur.tenant_id = ?", subjectID, t).
		Distinct().
		Pluck("p.code", &codes).Error; err != nil {
		return nil, err
	}
	return codes, nil
}

func (x authzRepo) EffectiveGrantPermissions(ctx context.Context, subjectID string, now time.Time) ([]string, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	var codes []string
	if err := db.Table("rbac_user_grants AS ug").
		Joins("JOIN rbac_permissions p ON p.id = ug.permission_id AND p.status = ?", model.PermissionStatusEnabled).
		Where("ug.tenant_id = ? AND ug.subject_id = ? AND ug.revoked_at IS NULL AND (ug.expires_at IS NULL OR ug.expires_at > ?)", t, subjectID, now).
		Distinct().
		Pluck("p.code", &codes).Error; err != nil {
		return nil, err
	}
	return codes, nil
}

// HasBuiltinSuperAdminRole 判定本域或平台域（tenant_id=”）的内置超管角色
// （§2.9 平台/租户边界）：平台超管对全部租户生效，租户超管仅本域生效。
func (x authzRepo) HasBuiltinSuperAdminRole(ctx context.Context, subjectID string) (bool, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return false, err
	}
	var n int64
	if err := db.Table("rbac_user_roles AS ur").
		Joins("JOIN rbac_roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id").
		Where("ur.subject_id = ? AND ur.tenant_id IN (?, '') AND r.code = ? AND r.is_builtin = ? AND r.status = ?",
			subjectID, t, model.BuiltinSuperAdminRoleCode, true, model.RoleStatusEnabled).
		Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

func (x authzRepo) NearestGrantExpiry(ctx context.Context, subjectID string, now time.Time) (*time.Time, error) {
	db, t, err := x.r.writer(ctx)
	if err != nil {
		return nil, err
	}
	// MIN() 空集返回 NULL：sql.NullTime 承接（同 base 仓储，§6.5）。
	var nullTime sql.NullTime
	if err := db.Table("rbac_user_grants").
		Select("MIN(expires_at)").
		Where("tenant_id = ? AND subject_id = ? AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at > ?", t, subjectID, now).
		Scan(&nullTime).Error; err != nil {
		return nil, err
	}
	if nullTime.Valid {
		return &nullTime.Time, nil
	}
	return nil, nil
}

var _ repository.RoleRepo = roleRepo{}
var _ repository.UserRoleRepo = userRoleRepo{}
var _ repository.UserGrantRepo = grantRepo{}
var _ repository.AuthorizationRepo = authzRepo{}
