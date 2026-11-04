package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
)

// ServiceDeps 汇聚管理服务所需的依赖。由 rbac.New 统一装配。
type ServiceDeps struct {
	Roles           repository.RoleRepo
	Permissions     repository.PermissionRepo
	UserRoles       repository.UserRoleRepo
	RolePermissions repository.RolePermissionRepo
	Grants          repository.UserGrantRepo
	Registry        *registry.Registry
	// Authorizer 用于"授权者必须持有拟授予权限"约束（§2.2）与缓存失效。
	Authorizer *AuthorizationService
	// Events 授权变更事件总线（nil 时事件被丢弃）。
	Events *EventBus
	// GrantorMustHold 默认开启；关闭用于"权限管理员不需要持有全部业务权限"的场景。
	GrantorMustHold bool
}

// grantorAllowed 校验授权者约束：operator 必须持有全部拟授予权限码，
// 超级管理员除外（§2.2）。零权限码（如空角色）不构成提权，直接放行。
func (d ServiceDeps) grantorAllowed(ctx context.Context, operator AuthorizationContext, codes []string) error {
	if !d.GrantorMustHold || len(codes) == 0 {
		return nil
	}
	isSuper, err := d.Authorizer.IsSuperAdministrator(ctx, operator)
	if err != nil {
		return err
	}
	if isSuper {
		return nil
	}
	ok, err := d.Authorizer.HasAllPermissions(ctx, operator, codes...)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrGrantorPermissionDenied, strings.Join(codes, ", "))
	}
	return nil
}

// record 分发授权变更事件（事件失败向上传播并标记"提交后失败"哨兵，§2.10/§6.7）。
func (d ServiceDeps) record(ctx context.Context, e Event) error {
	if d.Events == nil {
		return nil
	}
	if err := d.Events.Record(ctx, e); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditFailedAfterCommit, err)
	}
	return nil
}

// invalidateSubject / invalidateSubjects / invalidateEpoch：失效包装。
// 数据库已提交、递增失败时返回 ErrInvalidationFailedAfterCommit（重试同一操作安全）。
func (d ServiceDeps) invalidateSubject(ctx context.Context, subjectID SubjectID) error {
	if err := d.Authorizer.IncrSubjectVersion(ctx, subjectID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidationFailedAfterCommit, err)
	}
	return nil
}

func (d ServiceDeps) invalidateSubjects(ctx context.Context, subjectIDs []string) error {
	for _, id := range subjectIDs {
		if err := d.invalidateSubject(ctx, SubjectID(id)); err != nil {
			return err
		}
	}
	return nil
}

func (d ServiceDeps) invalidateEpoch(ctx context.Context) error {
	if err := d.Authorizer.IncrEpoch(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidationFailedAfterCommit, err)
	}
	return nil
}

// RoleService 角色管理（§2.4）。方法首个参数 operator 为操作者授权上下文，
// 用于授权者约束与审计事件。
//
// Security：本服务不鉴权 operator——不检查调用者是否持有 rbac:* 管理权限。
// HTTP 管理接口、内部 Job、CLI 等所有调用方必须先自行完成调用者授权
// （如经 guard.Require("rbac:role:create") 保护），Service 只执行业务规则
// （授权者持权约束等）而非入口鉴权。
type RoleService struct {
	deps ServiceDeps
}

// NewRoleService 构造角色服务。
func NewRoleService(deps ServiceDeps) *RoleService { return &RoleService{deps: deps} }

// Create 创建角色（启用状态，非内置）。
func (s *RoleService) Create(ctx context.Context, operator AuthorizationContext, code, name, description string) (*model.Role, error) {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	code = strings.TrimSpace(code)
	if code == "" || len(code) > model.RoleCodeMaxLength {
		return nil, fmt.Errorf("%w: %q", ErrInvalidRoleCode, code)
	}
	if strings.TrimSpace(name) == "" || len(name) > model.NameMaxLength {
		return nil, fmt.Errorf("%w: name required (1-%d chars)", ErrInvalidPermissionDef, model.NameMaxLength)
	}
	if len(description) > model.DescMaxLength {
		return nil, fmt.Errorf("%w: description too long (max %d chars)", ErrInvalidPermissionDef, model.DescMaxLength)
	}
	if existing, err := s.deps.Roles.FindByCode(ctx, code); err == nil && existing != nil {
		return nil, fmt.Errorf("%w: %s", ErrRoleCodeExists, code)
	} else if !errors.Is(err, repository.ErrRecordNotFound) {
		return nil, err
	}

	role := &model.Role{
		Code:        code,
		Name:        name,
		Description: description,
		Status:      model.RoleStatusEnabled,
	}
	if err := s.deps.Roles.Create(ctx, role); err != nil {
		// 并发同 code 的"先查后插"竞态：唯一键兜底，映射为领域错误。
		if repository.IsDuplicate(err) {
			return nil, fmt.Errorf("%w: %s", ErrRoleCodeExists, code)
		}
		return nil, err
	}
	if err := s.deps.record(ctx, NewEvent(EventRoleCreated, operator, code, map[string]string{
		"role_id": strconv.FormatUint(role.ID, 10),
		"name":    name,
	})); err != nil {
		return nil, err
	}
	return role, nil
}

// Get 按 ID 查询角色。
func (s *RoleService) Get(ctx context.Context, id uint64) (*model.Role, error) {
	role, err := s.deps.Roles.FindByID(ctx, id)
	if errors.Is(err, repository.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: id=%d", ErrRoleNotFound, id)
	}
	return role, err
}

// FindByCode 按角色代码查询。
func (s *RoleService) FindByCode(ctx context.Context, code string) (*model.Role, error) {
	role, err := s.deps.Roles.FindByCode(ctx, code)
	if errors.Is(err, repository.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: code=%s", ErrRoleNotFound, code)
	}
	return role, err
}

// List 按过滤条件查询角色。
func (s *RoleService) List(ctx context.Context, f repository.RoleFilter) ([]model.Role, error) {
	return s.deps.Roles.List(ctx, f)
}

// Update 修改角色展示元数据（name/description）。code 与 status 不可经此修改。
// 内置角色允许更新展示信息，但不可删除/禁用（§2.4）。
func (s *RoleService) Update(ctx context.Context, operator AuthorizationContext, id uint64, name, description string) error {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	role, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || len(name) > model.NameMaxLength {
		return fmt.Errorf("%w: name required (1-%d chars)", ErrInvalidPermissionDef, model.NameMaxLength)
	}
	if len(description) > model.DescMaxLength {
		return fmt.Errorf("%w: description too long (max %d chars)", ErrInvalidPermissionDef, model.DescMaxLength)
	}
	if err := s.deps.Roles.UpdateProfile(ctx, id, name, description); err != nil {
		return err
	}
	return s.deps.record(ctx, NewEvent(EventRoleUpdated, operator, role.Code, map[string]string{
		"role_id": strconv.FormatUint(id, 10),
		"name":    name,
	}))
}

// SetStatus 启用/禁用角色。内置角色受保护（§7.3）。
// 状态变化后批量递增关联用户版本号（§6.3 失效矩阵）。
func (s *RoleService) SetStatus(ctx context.Context, operator AuthorizationContext, id uint64, status uint8) error {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	role, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if role.IsBuiltin {
		return fmt.Errorf("%w: cannot disable/enable builtin role %s", ErrBuiltinRoleProtected, role.Code)
	}
	if status != model.RoleStatusEnabled && status != model.RoleStatusDisabled {
		return fmt.Errorf("rbac: invalid role status %d", status)
	}
	if role.Status == status {
		return nil // 幂等：状态未变化
	}
	if err := s.deps.Roles.SetStatus(ctx, id, status); err != nil {
		return err
	}
	if err := s.incrRoleSubjectVersions(ctx, id); err != nil {
		return err
	}
	return s.deps.record(ctx, NewEvent(EventRoleStatusChanged, operator, role.Code, map[string]string{
		"role_id": strconv.FormatUint(id, 10),
		"from":    strconv.FormatUint(uint64(role.Status), 10),
		"to":      strconv.FormatUint(uint64(status), 10),
	}))
}

// Delete 删除角色：内置角色受保护；正在被分配给用户的角色拒绝删除（§2.4）。
// 删除时在同一事务清理关联行（§5.3）。
func (s *RoleService) Delete(ctx context.Context, operator AuthorizationContext, id uint64) error {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	role, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if role.IsBuiltin {
		return fmt.Errorf("%w: cannot delete builtin role %s", ErrBuiltinRoleProtected, role.Code)
	}
	n, err := s.deps.Roles.CountUsers(ctx, id)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: %d subject(s)", ErrRoleInUse, n)
	}
	if err := s.deps.Roles.DeleteWithAssociations(ctx, id); err != nil {
		return err
	}
	return s.deps.record(ctx, NewEvent(EventRoleDeleted, operator, role.Code, map[string]string{
		"role_id": strconv.FormatUint(id, 10),
	}))
}

// SetPermissions 将角色权限集合整体替换为给定权限码集合（差量事务）。
//
// 校验链：
//   - 角色存在；内置角色禁止权限分配（§7.3）
//   - 每个权限码必须在 Registry 注册（§2.2：只能引用已注册权限）
//   - 每个权限必须处于启用状态
//   - 授权者必须持有全部拟授予权限（§2.2，默认开启；超管除外）
//
// 提交成功后批量递增拥有该角色的用户版本号（§6.3）。
func (s *RoleService) SetPermissions(ctx context.Context, operator AuthorizationContext, roleID uint64, permissionCodes []string) error {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	role, err := s.Get(ctx, roleID)
	if err != nil {
		return err
	}
	if role.IsBuiltin {
		return fmt.Errorf("%w: cannot assign permissions to builtin role %s", ErrBuiltinRoleProtected, role.Code)
	}

	permIDs, err := s.resolveEnabledPermissionIDs(ctx, permissionCodes)
	if err != nil {
		return err
	}
	if err := s.deps.grantorAllowed(ctx, operator, permissionCodes); err != nil {
		return err
	}

	if err := s.deps.RolePermissions.SetPermissions(ctx, roleID, permIDs); err != nil {
		return err
	}
	if err := s.incrRoleSubjectVersions(ctx, roleID); err != nil {
		return err
	}
	return s.deps.record(ctx, NewEvent(EventRolePermissionsChanged, operator, role.Code, map[string]string{
		"role_id":    strconv.FormatUint(roleID, 10),
		"codes":      strings.Join(permissionCodes, ","),
		"code_count": strconv.Itoa(len(permissionCodes)),
	}))
}

// PermissionsOfRole 返回角色当前关联的权限（展示用，含禁用/废弃状态）。
func (s *RoleService) PermissionsOfRole(ctx context.Context, roleID uint64) ([]model.Permission, error) {
	if _, err := s.Get(ctx, roleID); err != nil {
		return nil, err
	}
	return s.deps.RolePermissions.PermissionsOfRole(ctx, roleID)
}

// SubjectsOfRole 返回角色关联的用户标识（§2.4 查询角色关联用户）。
func (s *RoleService) SubjectsOfRole(ctx context.Context, roleID uint64) ([]string, error) {
	if _, err := s.Get(ctx, roleID); err != nil {
		return nil, err
	}
	return s.deps.UserRoles.SubjectIDsOfRole(ctx, roleID)
}

// resolveEnabledPermissionIDs 将权限码解析为启用状态的权限 ID。
// 逐条校验：Registry 已注册 + 数据库存在 + 状态启用。
func (s *RoleService) resolveEnabledPermissionIDs(ctx context.Context, codes []string) ([]uint64, error) {
	if len(codes) == 0 {
		return nil, nil
	}
	unique := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		if !s.deps.Registry.Has(c) {
			return nil, fmt.Errorf("%w: %s is not registered", ErrPermissionNotFound, c)
		}
		unique[c] = struct{}{}
	}
	distinct := make([]string, 0, len(unique))
	for c := range unique {
		distinct = append(distinct, c)
	}
	// 排序保证确定性行为（map 迭代顺序随机，会传导到 SetPermissions 的入参顺序）。
	sort.Strings(distinct)
	perms, err := s.deps.Permissions.FindByCodes(ctx, distinct)
	if err != nil {
		return nil, err
	}
	byCode := make(map[string]model.Permission, len(perms))
	for _, p := range perms {
		byCode[p.Code] = p
	}
	ids := make([]uint64, 0, len(distinct))
	for _, c := range distinct {
		p, ok := byCode[c]
		if !ok {
			return nil, fmt.Errorf("%w: %s is registered but missing from database (run SyncPermissions)", ErrPermissionNotFound, c)
		}
		if p.Status != model.PermissionStatusEnabled {
			return nil, fmt.Errorf("%w: %s", ErrPermissionDisabled, c)
		}
		ids = append(ids, p.ID)
	}
	return ids, nil
}

// incrRoleSubjectVersions 批量递增角色关联用户的版本号（§6.3 角色权限变更）。
// 失效失败时返回错误：管理接口不得在失效失败时静默报成功（§6.6）。
func (s *RoleService) incrRoleSubjectVersions(ctx context.Context, roleID uint64) error {
	subjects, err := s.deps.UserRoles.SubjectIDsOfRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("rbac: load role subjects for invalidation: %w", err)
	}
	return s.deps.invalidateSubjects(ctx, subjects)
}
