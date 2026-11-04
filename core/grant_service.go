package core

import (
	"context"
	"fmt"
	"time"

	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/repository"
)

// GrantService 用户额外授权管理（§2.5），完整生命周期：
// 过期/撤销记录保留不删除；重新授权 = 撤销旧活跃行 + 插入新行。
type GrantService struct {
	deps ServiceDeps
}

// NewGrantService 构造额外授权服务。
func NewGrantService(deps ServiceDeps) *GrantService { return &GrantService{deps: deps} }

// Grant 向用户授予额外权限。
//
// 校验链：
//   - subject_id 合法；权限码已在 Registry 注册且数据库中处于启用状态
//   - 授权者必须持有拟授予权限（§2.2，默认开启；超管除外）
//   - 到期时间必须在未来（可选，NULL=永久）
//
// 落库为单事务：先撤销同 (subject_id, permission_id) 的未撤销行（含已过期），
// 再插入新授权（§2.5 主防线；生成列唯一约束兜底并发）。
// 提交成功后递增该用户版本号（§6.3）。
func (s *GrantService) Grant(ctx context.Context, operator AuthorizationContext, subjectID, permissionCode string, expiresAt *time.Time, reason string) error {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	if err := validateSubject(subjectID); err != nil {
		return err
	}
	perm, err := s.resolveEnabledPermission(ctx, permissionCode)
	if err != nil {
		return err
	}
	if len(reason) > model.DescMaxLength {
		return fmt.Errorf("%w: reason too long (max %d chars)", ErrInvalidPermissionDef, model.DescMaxLength)
	}
	now := time.Now().UTC()
	if expiresAt != nil && !expiresAt.After(now) {
		return fmt.Errorf("%w: %s", ErrInvalidGrantExpiry, expiresAt.Format(time.RFC3339))
	}
	if err := s.deps.grantorAllowed(ctx, operator, []string{permissionCode}); err != nil {
		return err
	}

	g := model.UserGrant{
		SubjectID:    subjectID,
		PermissionID: perm.ID,
		ExpiresAt:    expiresAt,
		Reason:       reason,
		CreatedBy:    operator.SubjectID.String(),
	}
	if err := s.deps.Grants.Grant(ctx, g, now); err != nil {
		return err
	}
	if err := s.deps.Authorizer.IncrSubjectVersion(ctx, SubjectID(subjectID)); err != nil {
		return err
	}
	detail := map[string]string{"permission": permissionCode, "reason": reason}
	if expiresAt != nil {
		detail["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	return s.deps.record(ctx, NewEvent(EventUserGranted, operator, subjectID, detail))
}

// Revoke 撤销用户当前活跃的额外授权（保留记录，§2.5）。
// 无活跃授权时返回 ErrGrantNotFound。
func (s *GrantService) Revoke(ctx context.Context, operator AuthorizationContext, subjectID, permissionCode string) error {
	ctx = ContextWithTenant(ctx, operator.TenantID)

	if err := validateSubject(subjectID); err != nil {
		return err
	}
	perm, err := s.resolveEnabledPermission(ctx, permissionCode)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	rows, err := s.deps.Grants.Revoke(ctx, subjectID, perm.ID, operator.SubjectID.String(), now)
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: subject=%s permission=%s", ErrGrantNotFound, subjectID, permissionCode)
	}
	if err := s.deps.Authorizer.IncrSubjectVersion(ctx, SubjectID(subjectID)); err != nil {
		return err
	}
	return s.deps.record(ctx, NewEvent(EventGrantRevoked, operator, subjectID, map[string]string{
		"permission": permissionCode,
	}))
}

// FindActive 返回当前未撤销的授权记录（无论是否已到期）。
func (s *GrantService) FindActive(ctx context.Context, subjectID, permissionCode string) (*model.UserGrant, error) {
	perm, err := s.resolveEnabledPermission(ctx, permissionCode)
	if err != nil {
		return nil, err
	}
	g, err := s.deps.Grants.FindActive(ctx, subjectID, perm.ID)
	if repository.IsNotFound(err) {
		return nil, fmt.Errorf("%w: subject=%s permission=%s", ErrGrantNotFound, subjectID, permissionCode)
	}
	return g, err
}

// List 返回用户全部授权历史（含已撤销/已过期，审计视角）。
func (s *GrantService) List(ctx context.Context, subjectID string) ([]model.UserGrant, error) {
	if err := validateSubject(subjectID); err != nil {
		return nil, err
	}
	return s.deps.Grants.ListBySubject(ctx, subjectID)
}

// ListActive 返回用户未撤销且未到期的授权。
func (s *GrantService) ListActive(ctx context.Context, subjectID string) ([]model.UserGrant, error) {
	if err := validateSubject(subjectID); err != nil {
		return nil, err
	}
	return s.deps.Grants.ListActiveBySubject(ctx, subjectID, time.Now().UTC())
}

// resolveEnabledPermission 解析权限码：Registry 已注册 + 数据库启用。
func (s *GrantService) resolveEnabledPermission(ctx context.Context, code string) (*model.Permission, error) {
	if !s.deps.Registry.Has(code) {
		return nil, fmt.Errorf("%w: %s is not registered", ErrPermissionNotFound, code)
	}
	perm, err := s.deps.Permissions.FindByCode(ctx, code)
	if repository.IsNotFound(err) {
		return nil, fmt.Errorf("%w: %s is registered but missing from database (run SyncPermissions)", ErrPermissionNotFound, code)
	}
	if err != nil {
		return nil, err
	}
	if perm.Status != model.PermissionStatusEnabled {
		return nil, fmt.Errorf("%w: %s", ErrPermissionDisabled, code)
	}
	return perm, nil
}
