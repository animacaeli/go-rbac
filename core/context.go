package core

import (
	"context"

	"github.com/animacaeli/go-rbac/internal/repository"
)

// ContextWithTenant 将租户标识写入 ctx（空串 = default 域 / 平台域）。
// 多租户部署的读路径应在请求入口用 TenantResolver 解析后注入；
// 写路径由服务层从 operator AuthorizationContext 自动注入。
// 槽位实现位于 internal/repository（仓储层据此派生权威计数器键与查询过滤）。
func ContextWithTenant(ctx context.Context, tenantID string) context.Context {
	return repository.WithTenant(ctx, tenantID)
}

// TenantFromContext 读取 ctx 中的租户标识。
func TenantFromContext(ctx context.Context) (tenantID string, ok bool) {
	return repository.TenantFromContext(ctx)
}

// SubjectID 是外部用户标识（§4.2）。RBAC 不管理业务用户表，
// 用户身份必须来自业务项目已完成认证的可信上下文。
type SubjectID string

// String 返回字符串形式。
func (s SubjectID) String() string { return string(s) }

// IsEmpty 报告标识是否为空（空标识必然非法）。
func (s SubjectID) IsEmpty() bool { return s == "" }

// DefaultScope 是单租户模式的授权域（§6.1）。
// v1 scope 槽位定死：多租户上线后只改取值不改形状。
const DefaultScope = "default"

// AuthorizationContext 是显式化的授权域上下文（§4.2）。
// Authorizer 的全部方法接受本结构而非裸 SubjectID。
type AuthorizationContext struct {
	// SubjectID 外部用户标识，在同一个授权域内必须唯一。
	SubjectID SubjectID

	// TenantID 授权域。v1 单租户模式恒为空串（映射到 default 域）；
	// 多租户启用后必须提供，缺失即 fail closed。
	// v1 传入非空值会得到 ErrTenantNotSupported（同样 fail closed）。
	TenantID string
}

// Validate 校验上下文主体标识（非空且不超长）。
//
// 注意租户语义：本方法不感知租户策略。未启用 tenant 模块时（v1），
// AuthorizationService 会拒绝非空 TenantID（ErrTenantNotSupported）；
// 启用后改为要求非空（ErrTenantRequired）。需要按策略校验时，
// 请使用 Authorizer 的方法（其内部按当前策略校验）。
func (ac AuthorizationContext) Validate(maxSubjectIDLen int) error {
	if ac.SubjectID.IsEmpty() || len(ac.SubjectID) > maxSubjectIDLen {
		return ErrInvalidSubjectID
	}
	if ac.TenantID != "" {
		// 保持向后兼容的 v1 严格语义；租户部署下请勿依赖本方法判定租户。
		return ErrTenantNotSupported
	}
	return nil
}

// Scope 返回授权域名（§6.1）。v1 恒为 default。
func (ac AuthorizationContext) Scope() string {
	if ac.TenantID == "" {
		return DefaultScope
	}
	return ac.TenantID
}
