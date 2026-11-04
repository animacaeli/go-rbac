package core

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/model"
)

// UserRoleService 用户角色关联管理（§2.2）。
//
// Security：本服务不鉴权 operator——不检查调用者是否持有 rbac:* 管理权限。
// HTTP 管理接口、内部 Job、CLI 等所有调用方必须先自行完成调用者授权
// （如经 guard.Require("rbac:role:create") 保护），Service 只执行业务规则
// （授权者持权约束等）而非入口鉴权。
type UserRoleService struct {
	deps ServiceDeps
}

// NewUserRoleService 构造用户角色服务。
func NewUserRoleService(deps ServiceDeps) *UserRoleService {
	return &UserRoleService{deps: deps}
}

// validateSubject 校验外部用户标识。
func validateSubject(subjectID string) error {
	if subjectID == "" || len(subjectID) > model.SubjectIDMaxLength {
		return fmt.Errorf("%w: %q", ErrInvalidSubjectID, subjectID)
	}
	return nil
}

// Assign 为用户分配角色（幂等）。
//
// 校验链（§7.3 / §2.2）：
//   - 角色存在；内置超管角色禁止经管理接口授予
//   - 授权者约束：operator 必须持有该角色当前全部启用权限（超管除外；
//     空权限角色不构成提权，直接放行）
//
// 提交成功后递增该用户版本号（§6.3）。
func (s *UserRoleService) Assign(ctx context.Context, operator AuthorizationContext, subjectID string, roleID uint64) error {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	if err := validateSubject(subjectID); err != nil {
		return err
	}
	role, err := s.deps.Roles.FindByID(ctx, roleID)
	if repository.IsNotFound(err) {
		return fmt.Errorf("%w: id=%d", ErrRoleNotFound, roleID)
	}
	if err != nil {
		return err
	}
	if role.IsBuiltin {
		return fmt.Errorf("%w: builtin role %s cannot be granted via management API", ErrBuiltinRoleProtected, role.Code)
	}

	codes, err := s.deps.RolePermissions.PermissionCodesOfRole(ctx, roleID)
	if err != nil {
		return err
	}
	if err := s.deps.grantorAllowed(ctx, operator, codes); err != nil {
		return err
	}

	if err := s.deps.UserRoles.Assign(ctx, subjectID, roleID); err != nil {
		return err
	}
	if err := s.deps.invalidateSubject(ctx, SubjectID(subjectID)); err != nil {
		return err
	}
	return s.deps.record(ctx, NewEvent(EventUserRoleAssigned, operator, subjectID, map[string]string{
		"role_id": strconv.FormatUint(roleID, 10),
		"role":    role.Code,
	}))
}

// AssignBatch 为一个用户批量分配多个角色：逐个校验内置保护，
// 授权者约束按全部角色的启用权限并集校验一次；提交后递增一次版本号。
func (s *UserRoleService) AssignBatch(ctx context.Context, operator AuthorizationContext, subjectID string, roleIDs []uint64) error {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	if len(roleIDs) == 0 {
		return nil
	}
	if err := validateSubject(subjectID); err != nil {
		return err
	}

	var roleCodes []string
	codeSet := map[string]struct{}{}
	for _, roleID := range roleIDs {
		role, err := s.deps.Roles.FindByID(ctx, roleID)
		if repository.IsNotFound(err) {
			return fmt.Errorf("%w: id=%d", ErrRoleNotFound, roleID)
		}
		if err != nil {
			return err
		}
		if role.IsBuiltin {
			return fmt.Errorf("%w: builtin role %s cannot be granted via management API", ErrBuiltinRoleProtected, role.Code)
		}
		if _, seen := codeSet[role.Code]; !seen {
			codeSet[role.Code] = struct{}{}
			roleCodes = append(roleCodes, role.Code)
		}
	}

	// 授权者约束：按全部角色启用权限的并集校验。
	var allCodes []string
	seen := map[string]struct{}{}
	for _, roleID := range roleIDs {
		codes, err := s.deps.RolePermissions.PermissionCodesOfRole(ctx, roleID)
		if err != nil {
			return err
		}
		for _, c := range codes {
			if _, dup := seen[c]; !dup {
				seen[c] = struct{}{}
				allCodes = append(allCodes, c)
			}
		}
	}
	if err := s.deps.grantorAllowed(ctx, operator, allCodes); err != nil {
		return err
	}

	for _, roleID := range roleIDs {
		if err := s.deps.UserRoles.Assign(ctx, subjectID, roleID); err != nil {
			return err
		}
	}
	if err := s.deps.invalidateSubject(ctx, SubjectID(subjectID)); err != nil {
		return err
	}
	return s.deps.record(ctx, NewEvent(EventUserRoleAssigned, operator, subjectID, map[string]string{
		"role_ids": strings.Join(uint64s(roleIDs), ","),
		"roles":    strings.Join(roleCodes, ","),
	}))
}

// AssignRoleToSubjects 将一个角色批量分配给多个用户。
// 授权者约束按该角色校验一次；提交后递增每个用户版本号。
func (s *UserRoleService) AssignRoleToSubjects(ctx context.Context, operator AuthorizationContext, roleID uint64, subjectIDs []string) error {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	if len(subjectIDs) == 0 {
		return nil
	}
	role, err := s.deps.Roles.FindByID(ctx, roleID)
	if repository.IsNotFound(err) {
		return fmt.Errorf("%w: id=%d", ErrRoleNotFound, roleID)
	}
	if err != nil {
		return err
	}
	if role.IsBuiltin {
		return fmt.Errorf("%w: builtin role %s cannot be granted via management API", ErrBuiltinRoleProtected, role.Code)
	}
	for _, subjectID := range subjectIDs {
		if err := validateSubject(subjectID); err != nil {
			return err
		}
	}

	codes, err := s.deps.RolePermissions.PermissionCodesOfRole(ctx, roleID)
	if err != nil {
		return err
	}
	if err := s.deps.grantorAllowed(ctx, operator, codes); err != nil {
		return err
	}

	for _, subjectID := range subjectIDs {
		if err := s.deps.UserRoles.Assign(ctx, subjectID, roleID); err != nil {
			return err
		}
	}
	if err := s.deps.invalidateSubjects(ctx, subjectIDs); err != nil {
		return err
	}
	return s.deps.record(ctx, NewEvent(EventUserRoleAssigned, operator, role.Code, map[string]string{
		"role_id":       strconv.FormatUint(roleID, 10),
		"subject_ids":   strings.Join(subjectIDs, ","),
		"subject_count": strconv.Itoa(len(subjectIDs)),
	}))
}

// Revoke 回收用户角色（幂等：未分配时无操作）。
func (s *UserRoleService) Revoke(ctx context.Context, operator AuthorizationContext, subjectID string, roleID uint64) error {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	if err := validateSubject(subjectID); err != nil {
		return err
	}
	if err := s.deps.UserRoles.Revoke(ctx, subjectID, roleID); err != nil {
		return err
	}
	if err := s.deps.invalidateSubject(ctx, SubjectID(subjectID)); err != nil {
		return err
	}
	return s.deps.record(ctx, NewEvent(EventUserRoleRevoked, operator, subjectID, map[string]string{
		"role_id": strconv.FormatUint(roleID, 10),
	}))
}

// ListRoles 返回用户当前持有的角色（含禁用角色，调用方按需过滤）。
func (s *UserRoleService) ListRoles(ctx context.Context, subjectID string) ([]model.Role, error) {
	if err := validateSubject(subjectID); err != nil {
		return nil, err
	}
	return s.deps.UserRoles.ListRolesBySubject(ctx, subjectID)
}

// ListSubjects 返回角色关联的用户标识。
func (s *UserRoleService) ListSubjects(ctx context.Context, roleID uint64) ([]string, error) {
	return s.deps.UserRoles.SubjectIDsOfRole(ctx, roleID)
}

func uint64s(ids []uint64) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, strconv.FormatUint(id, 10))
	}
	return out
}
