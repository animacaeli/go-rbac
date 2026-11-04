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

	// ErrNoPermissionDeclared 表示权限码参数为空（fail closed，视为调用方编程错误）。
	ErrNoPermissionDeclared = errors.New("rbac: no permission declared")
)

// 管理服务错误。
var (
	ErrRoleNotFound            = errors.New("rbac: role not found")
	ErrInvalidRoleCode         = errors.New("rbac: invalid role code")
	ErrRoleCodeExists          = errors.New("rbac: role code already exists")
	ErrRoleInUse               = errors.New("rbac: role is assigned to subjects and cannot be deleted")
	ErrBuiltinRoleProtected    = errors.New("rbac: builtin role is protected from management operations")
	ErrPermissionNotFound      = errors.New("rbac: permission not found")
	ErrPermissionDisabled      = errors.New("rbac: permission disabled or deprecated")
	ErrGrantNotFound           = errors.New("rbac: active grant not found")
	ErrInvalidGrantExpiry      = errors.New("rbac: grant expiry must be in the future")
	ErrGrantorPermissionDenied = errors.New("rbac: grantor does not hold the permission being granted")

	// ErrInvalidPermissionDef 复用注册中心的定义校验错误（展示元数据非法）。
	ErrInvalidPermissionDef = registry.ErrInvalidPermissionDef
)
