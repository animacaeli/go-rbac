// Package middleware 提供与框架无关的鉴权中间件骨架与决策类型（§3.3）。
//
// 框架适配器（adapter/gin 等）按"逃生舱规则"完全自包含，不共享本包胶水；
// 本骨架服务于自定义集成场景（如 gRPC、非内置框架），将 §2.6 的鉴权顺序
// 与错误语义集中在一处。
package middleware

import (
	"context"
	"errors"

	"github.com/animacaeli/go-rbac/core"
)

// Decision 是一次鉴权的裁决结果，对应 §2.6 错误语义表。
type Decision uint8

const (
	// DecisionAllow 授权通过，进入业务处理。
	DecisionAllow Decision = iota

	// DecisionUnauthenticated 未认证（身份解析失败），HTTP 401。
	DecisionUnauthenticated

	// DecisionForbidden 已认证但无权限或账号非活跃，HTTP 403。
	DecisionForbidden

	// DecisionUnavailable 鉴权服务异常（fail closed），HTTP 500/503。
	DecisionUnavailable
)

// Result 是鉴权裁决及其错误细节。
type Result struct {
	Decision Decision
	// Err 为 nil（通过/无权限）或底层错误（401/403/500 的原因）。
	Err error
	// SubjectID 为解析成功的主体标识（仅 Allow/Forbidden/Unavailable 时有效）。
	SubjectID core.SubjectID
}

// Authorize 执行 §2.6 鉴权顺序的框架无关部分：
// 身份解析 → （授权服务内部完成状态检查与授权判断）→ 裁决。
//
// eval 由调用方提供，选择 Authorizer 的判定方法（Has/HasAny/HasAll）。
// 错误映射：
//   - 解析失败 → Unauthenticated（不得视为匿名授权通过）
//   - core.ErrSubjectInactive → Forbidden（确定拒绝）
//   - 其他错误 → Unavailable（fail closed，不得放行）
func Authorize(
	ctx context.Context,
	authz core.Authorizer,
	resolver core.SubjectResolver,
	eval func(ctx context.Context, ac core.AuthorizationContext) (bool, error),
) Result {
	subjectID, err := resolver.Resolve(ctx)
	if err != nil {
		return Result{Decision: DecisionUnauthenticated, Err: err}
	}
	ac := core.AuthorizationContext{SubjectID: subjectID}

	ok, err := eval(ctx, ac)
	if err != nil {
		if errors.Is(err, core.ErrSubjectInactive) {
			return Result{Decision: DecisionForbidden, Err: err, SubjectID: subjectID}
		}
		return Result{Decision: DecisionUnavailable, Err: err, SubjectID: subjectID}
	}
	if !ok {
		return Result{Decision: DecisionForbidden, SubjectID: subjectID}
	}
	return Result{Decision: DecisionAllow, SubjectID: subjectID}
}
