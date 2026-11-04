package core

import (
	"context"
	"fmt"
	"strconv"

	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/repository"
)

// PermissionService 权限资源管理（§2.3）：状态控制与查询。
// 新增/元数据/废弃由 Registry 同步机制负责（registry.Sync），不经此服务。
type PermissionService struct {
	deps ServiceDeps
}

// NewPermissionService 构造权限服务。
func NewPermissionService(deps ServiceDeps) *PermissionService {
	return &PermissionService{deps: deps}
}

// SetStatus 设置权限状态（启用/手动禁用）。
//
// §6.3 失效矩阵：权限禁用 → INCR 全局 epoch——一次性使所有旧生成键不可达，
// 代价是全员冷启动一次。启用同样递增 epoch（保守失效，确保从"禁用中"缓存
// 恢复的读者拿到新状态）。内置 rbac:* 权限允许禁用（运营决策），
// 禁用后相关管理接口将拒绝持权约束检查中依赖它的操作。
func (s *PermissionService) SetStatus(ctx context.Context, operator AuthorizationContext, code string, status uint8) error {
	if status != model.PermissionStatusEnabled && status != model.PermissionStatusDisabled {
		return fmt.Errorf("rbac: invalid permission status %d", status)
	}
	perm, err := s.deps.Permissions.FindByCode(ctx, code)
	if repository.IsNotFound(err) {
		return fmt.Errorf("%w: %s (not synced to database?)", ErrPermissionNotFound, code)
	}
	if err != nil {
		return err
	}
	if perm.Status == status {
		return nil // 幂等
	}
	if err := s.deps.Permissions.SetStatus(ctx, perm.ID, status); err != nil {
		return err
	}
	if err := s.deps.Authorizer.IncrEpoch(ctx); err != nil {
		return err
	}
	return s.deps.record(ctx, NewEvent(EventPermissionStatusSet, operator, code, map[string]string{
		"from": strconv.FormatUint(uint64(perm.Status), 10),
		"to":   strconv.FormatUint(uint64(status), 10),
	}))
}

// Get 按权限码查询。
func (s *PermissionService) Get(ctx context.Context, code string) (*model.Permission, error) {
	perm, err := s.deps.Permissions.FindByCode(ctx, code)
	if repository.IsNotFound(err) {
		return nil, fmt.Errorf("%w: %s", ErrPermissionNotFound, code)
	}
	return perm, err
}

// ListAll 返回全部权限（按 code 排序）。
func (s *PermissionService) ListAll(ctx context.Context) ([]model.Permission, error) {
	return s.deps.Permissions.ListAll(ctx)
}
