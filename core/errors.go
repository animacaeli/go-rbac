package core

import (
	"errors"

	"github.com/animacaeli/go-rbac/registry"
)

// 上下文与授权路径错误。所有错误都是哨兵错误，调用方用 errors.Is 判断。
var (
	// ErrInvalidSubjectID 表示 subject_id 为空或超长（VARCHAR(128)）。
	ErrInvalidSubjectID = errors.New("rbac: invalid subject id")

	// ErrSubjectInactive 表示账号状态检查判定主体非活跃（对应 HTTP 403，§2.6）。
	// 与基础设施错误区分开：非活跃是"确定拒绝"，不是"无法判断"。
	ErrSubjectInactive = errors.New("rbac: subject inactive")

	// ErrTenantNotSupported 表示 v1 未启用多租户但携带了 TenantID（fail closed，§2.9）。
	ErrTenantNotSupported = errors.New("rbac: tenant not supported in v1, TenantID must be empty (default scope)")

	// ErrTenantRequired 表示已启用多租户（tenant 模块）但 TenantID 缺失——
	// fail closed，不得回退到 default 域（§2.9）。
	ErrTenantRequired = errors.New("rbac: tenant id required (multi-tenant enabled, missing means fail closed)")

	// ErrInvalidTenantID 表示租户标识超长、含非法字符或占用了保留名
	// （"default" 是平台域 scope，"!global" 是全局计数器 scope）。非法字符
	// 会破坏缓存/计数器键结构，必须 fail closed。
	ErrInvalidTenantID = errors.New("rbac: invalid tenant id")

	// ErrNoPermissionDeclared 表示权限码参数为空（fail closed，视为调用方编程错误）。
	ErrNoPermissionDeclared = errors.New("rbac: no permission declared")

	// ErrCounterOverflow 表示权威计数器超出生成键的数值边界
	// （主体版本必须 < 2^32；epoch + 全局 epoch 必须 <= 2^31-1）。
	// 命中时 fail closed：拒绝鉴权而不是产生可能碰撞的生成键。
	ErrCounterOverflow = errors.New("rbac: counter exceeds generation key bounds")
)

// 管理服务错误。
var (
	ErrRoleNotFound                  = errors.New("rbac: role not found")
	ErrInvalidRoleCode               = errors.New("rbac: invalid role code")
	ErrRoleCodeExists                = errors.New("rbac: role code already exists")
	ErrRoleInUse                     = errors.New("rbac: role is assigned to subjects and cannot be deleted")
	ErrBuiltinRoleProtected          = errors.New("rbac: builtin role is protected from management operations")
	ErrPermissionNotFound            = errors.New("rbac: permission not found")
	ErrPermissionDisabled            = errors.New("rbac: permission disabled or deprecated")
	ErrGrantNotFound                 = errors.New("rbac: active grant not found")
	ErrInvalidGrantExpiry            = errors.New("rbac: grant expiry must be in the future")
	ErrInvalidationFailedAfterCommit = errors.New("rbac: invalidation failed after commit (retry semantics vary by operation, see docs)")

	// ErrAuditFailedAfterCommit 表示数据库变更已提交、但审计事件写入失败
	// （Strict 策略，§2.10/§6.7）。重试同一操作是安全的。
	ErrAuditFailedAfterCommit = errors.New("rbac: audit record failed after commit (audit gap possible under Strict; see docs)")

	ErrGrantorPermissionDenied = errors.New("rbac: grantor does not hold the permission being granted")

	// ErrInvalidPermissionDef 复用注册中心的定义校验错误（展示元数据非法）。
	ErrInvalidPermissionDef = registry.ErrInvalidPermissionDef
)
