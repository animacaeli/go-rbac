// Package rbac 是面向 Go Web 后台项目的模块化 RBAC 权限基础设施库。
//
// 基础用法（§10 最终使用体验）：
//
//	app, err := rbac.New(
//	    rbac.WithDB(db),
//	    rbac.WithPermissionRegistry(registry),
//	)
//	if err := app.Migrate(ctx); err != nil { panic(err) }
//	if _, err := app.SyncPermissions(ctx); err != nil { panic(err) }
//
//	guard := ginadapter.New(app.Authorizer(), resolver)
//	api.GET("/users", guard.Require("user:list"), handler)
//
// 设计文档：docs/go-rbac-design.md（v0.3.0-design 定稿）。
package rbac

import (
	"errors"

	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/registry"
)

// ErrDBRequired 表示未注入数据库句柄。
var ErrDBRequired = errors.New("rbac: WithDB is required")

// 公开错误面：库内哨兵错误的别名（§3.4：公开 API 面最小化，
// Repository 接口保持内部）。
var (
	// 授权路径。
	ErrInvalidSubjectID     = core.ErrInvalidSubjectID
	ErrSubjectInactive      = core.ErrSubjectInactive
	ErrTenantNotSupported   = core.ErrTenantNotSupported
	ErrNoPermissionDeclared = core.ErrNoPermissionDeclared

	// 管理服务。
	ErrRoleNotFound            = core.ErrRoleNotFound
	ErrInvalidRoleCode         = core.ErrInvalidRoleCode
	ErrRoleCodeExists          = core.ErrRoleCodeExists
	ErrRoleInUse               = core.ErrRoleInUse
	ErrBuiltinRoleProtected    = core.ErrBuiltinRoleProtected
	ErrPermissionNotFound      = core.ErrPermissionNotFound
	ErrPermissionDisabled      = core.ErrPermissionDisabled
	ErrGrantNotFound           = core.ErrGrantNotFound
	ErrInvalidGrantExpiry      = core.ErrInvalidGrantExpiry
	ErrGrantorPermissionDenied = core.ErrGrantorPermissionDenied

	// 注册中心。
	ErrInvalidPermissionCode = registry.ErrInvalidPermissionCode
	ErrDuplicateRegistration = registry.ErrDuplicateRegistration
	ErrInvalidPermissionDef  = registry.ErrInvalidPermissionDef
)

// 公开数据形状的类型别名：底层类型位于 internal（§3.4），别名让外部
// 可以命名与构造，而无法实现存储接口。
type (
	// RoleFilter 是角色列表过滤条件（App.Roles().List 的入参形状）。
	RoleFilter = repository.RoleFilter
)
