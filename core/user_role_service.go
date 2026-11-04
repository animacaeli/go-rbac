package core

import (
	"context"
	"fmt"

	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/repository"
)

// UserRoleService 用户角色关联管理（§2.2）。
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
func (s *UserRoleService) Assign(ctx context.Context, operator AuthorizationContext, subjectID string, roleID uint64) error {
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
	return s.deps.Authorizer.InvalidateSubject(ctx, SubjectID(subjectID))
}

// Revoke 回收用户角色（幂等：未分配时无操作）。
func (s *UserRoleService) Revoke(ctx context.Context, _ AuthorizationContext, subjectID string, roleID uint64) error {
	if err := validateSubject(subjectID); err != nil {
		return err
	}
	if err := s.deps.UserRoles.Revoke(ctx, subjectID, roleID); err != nil {
		return err
	}
	return s.deps.Authorizer.InvalidateSubject(ctx, SubjectID(subjectID))
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
