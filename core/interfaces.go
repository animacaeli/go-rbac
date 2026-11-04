package core

import (
	"context"
	"time"
)

// Authorizer 是统一授权服务接口（§4.3）。
//
// 错误语义（调用方必须区分）：
//   - 正常无权限：(false, nil)
//   - 权限查询失败：(false, err)——不得视为授权成功，fail closed
//   - 账号禁用：(false, ErrSubjectInactive)——确定拒绝（HTTP 403），非基础设施故障
type Authorizer interface {
	HasPermission(
		ctx context.Context,
		ac AuthorizationContext,
		permission string,
	) (bool, error)

	HasAnyPermission(
		ctx context.Context,
		ac AuthorizationContext,
		permissions ...string,
	) (bool, error)

	HasAllPermissions(
		ctx context.Context,
		ac AuthorizationContext,
		permissions ...string,
	) (bool, error)

	GetPermissions(
		ctx context.Context,
		ac AuthorizationContext,
	) ([]string, error)

	IsSuperAdministrator(
		ctx context.Context,
		ac AuthorizationContext,
	) (bool, error)
}

// SubjectResolver 由业务项目实现：从请求上下文解析 subject_id（§4.4）。
// 身份必须来自已完成认证的可信上下文；解析失败返回错误（对应 HTTP 401），
// 不得将请求视为匿名。
type SubjectResolver interface {
	Resolve(ctx context.Context) (SubjectID, error)
}

// SubjectStatusChecker 由业务项目可选实现：校验账号活跃状态（§4.4）。
// 账号状态由业务系统持有，RBAC 不存储。
// 返回 false 表示非活跃（拒绝，403）；返回 error 表示无法判断（fail closed，500）。
type SubjectStatusChecker interface {
	IsSubjectActive(ctx context.Context, subjectID SubjectID) (bool, error)
}

// Metrics 是可选观测接口（§4.6）。默认 NoopMetrics，不绑定具体实现。
type Metrics interface {
	// DenialsInc 按原因递增拒绝计数：unauthenticated / forbidden / unavailable。
	DenialsInc(reason string)

	// AuthorizeObserved 记录一次授权判断：是否缓存命中与耗时。
	AuthorizeObserved(cacheHit bool, d time.Duration)
}

// NoopMetrics 空实现。
type NoopMetrics struct{}

var _ Metrics = NoopMetrics{}

// DenialsInc 无操作。
func (NoopMetrics) DenialsInc(string) {}

// AuthorizeObserved 无操作。
func (NoopMetrics) AuthorizeObserved(bool, time.Duration) {}
