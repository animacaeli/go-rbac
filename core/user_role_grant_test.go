package core_test

import (
	"testing"
	"time"

	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// ---- UserRoleService ----

type UserRoleServiceSuite struct {
	serviceHarness
}

func (s *UserRoleServiceSuite) SetupTest() { s.setupHarness(true) }

func TestUserRoleServiceSuite(t *testing.T) { suite.Run(t, new(UserRoleServiceSuite)) }

func (s *UserRoleServiceSuite) TestAssign_GrantorHoldsRolePerms_Assigned() {
	// Arrange
	s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	normal := &model.Role{ID: 2, Code: "ops", Status: model.RoleStatusEnabled}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	s.rolePerms.On("PermissionCodesOfRole", mock.Anything, uint64(2)).
		Return([]string{"order:export"}, nil)
	s.expectGrantorHolds("order:export")
	s.userRoles.On("Assign", mock.Anything, subject, uint64(2)).Return(nil)

	// Act
	err := s.userRoleSvc.Assign(s.ctx, operator, subject, 2)

	// Assert
	s.Require().NoError(err)
}

func (s *UserRoleServiceSuite) TestAssign_BuiltinRole_Protected() {
	// Arrange
	builtin := &model.Role{ID: 1, Code: model.BuiltinSuperAdminRoleCode, IsBuiltin: true}
	s.roles.On("FindByID", mock.Anything, uint64(1)).Return(builtin, nil)

	// Act
	err := s.userRoleSvc.Assign(s.ctx, operator, subject, 1)

	// Assert：§7.3 管理接口不可授予内置超管角色。
	s.ErrorIs(err, core.ErrBuiltinRoleProtected)
}

func (s *UserRoleServiceSuite) TestAssign_GrantorLacksRolePerms_Rejected() {
	// Arrange
	normal := &model.Role{ID: 2, Code: "ops"}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	s.rolePerms.On("PermissionCodesOfRole", mock.Anything, uint64(2)).
		Return([]string{"order:export", "user:delete"}, nil)
	s.expectGrantorHolds("user:list")

	// Act
	err := s.userRoleSvc.Assign(s.ctx, operator, subject, 2)

	// Assert
	s.ErrorIs(err, core.ErrGrantorPermissionDenied)
}

func (s *UserRoleServiceSuite) TestAssign_EmptyRole_NoGrantorCheck() {
	// Arrange：空权限角色不构成提权，不做任何持权检查（authzRepo 无期望）。
	normal := &model.Role{ID: 3, Code: "empty"}
	s.roles.On("FindByID", mock.Anything, uint64(3)).Return(normal, nil)
	s.rolePerms.On("PermissionCodesOfRole", mock.Anything, uint64(3)).Return(nil, nil)
	s.userRoles.On("Assign", mock.Anything, subject, uint64(3)).Return(nil)

	// Act
	err := s.userRoleSvc.Assign(s.ctx, operator, subject, 3)

	// Assert
	s.Require().NoError(err)
}

func (s *UserRoleServiceSuite) TestAssign_InvalidSubject_Rejected() {
	tests := []string{"", makeLongString(129)}
	for _, sid := range tests {
		s.Run("subject_"+sid[:min(len(sid), 8)], func() {
			// Act
			err := s.userRoleSvc.Assign(s.ctx, operator, sid, 2)

			// Assert
			s.ErrorIs(err, core.ErrInvalidSubjectID)
		})
	}
}

func (s *UserRoleServiceSuite) TestAssign_RoleNotFound_Rejected() {
	// Arrange
	s.roles.On("FindByID", mock.Anything, uint64(99)).Return(nil, repository.ErrRecordNotFound)

	// Act
	err := s.userRoleSvc.Assign(s.ctx, operator, subject, 99)

	// Assert
	s.ErrorIs(err, core.ErrRoleNotFound)
}

func (s *UserRoleServiceSuite) TestRevoke_Idempotent() {
	// Arrange：普通角色可撤销（幂等——未分配时无操作）。
	normal := &model.Role{ID: 2, Code: "ops"}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	s.userRoles.On("Revoke", mock.Anything, subject, uint64(2)).Return(nil)

	// Act
	err := s.userRoleSvc.Revoke(s.ctx, operator, subject, 2)

	// Assert
	s.Require().NoError(err)
}

// P1-01（外部评审第七轮）：内置角色（含超管）不可经管理接口撤销。
func (s *UserRoleServiceSuite) TestRevoke_BuiltinRole_Protected() {
	// Arrange
	builtin := &model.Role{ID: 1, Code: model.BuiltinSuperAdminRoleCode, IsBuiltin: true}
	s.roles.On("FindByID", mock.Anything, uint64(1)).Return(builtin, nil)

	// Act
	err := s.userRoleSvc.Revoke(s.ctx, operator, subject, 1)

	// Assert
	s.ErrorIs(err, core.ErrBuiltinRoleProtected)
}

func (s *UserRoleServiceSuite) TestRevoke_RoleNotFound() {
	// Arrange
	s.roles.On("FindByID", mock.Anything, uint64(99)).Return(nil, repository.ErrRecordNotFound)

	// Act
	err := s.userRoleSvc.Revoke(s.ctx, operator, subject, 99)

	// Assert
	s.ErrorIs(err, core.ErrRoleNotFound)
}

func (s *UserRoleServiceSuite) TestRevoke_CrossTenantRole_Rejected() {
	// Arrange：acme 域内查 beta 角色 → 域过滤不可见（tenant 隔离仓储）。
	s.deps.TenancyRequired = true
	s.userRoleSvc = core.NewUserRoleService(s.deps)
	s.roles.On("FindByID", mock.Anything, uint64(7)).Return(nil, repository.ErrRecordNotFound)

	// Act
	err := s.userRoleSvc.Revoke(s.ctx, core.AuthorizationContext{TenantID: "acme", SubjectID: "op"}, subject, 7)

	// Assert
	s.ErrorIs(err, core.ErrRoleNotFound, "跨域角色在域内不可见即拒绝")
}

// ---- GrantService ----

type GrantServiceSuite struct {
	serviceHarness
}

func (s *GrantServiceSuite) SetupTest() { s.setupHarness(true) }

func TestGrantServiceSuite(t *testing.T) { suite.Run(t, new(GrantServiceSuite)) }

func (s *GrantServiceSuite) TestGrant_Permanent_Created() {
	// Arrange
	permsByCode := s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	perm := permsByCode["order:export"]
	s.perms.On("FindByCode", mock.Anything, "order:export").Return(&perm, nil)
	s.expectGrantorHolds("order:export")
	var stored model.UserGrant
	s.grants.On("Grant", mock.Anything, mock.AnythingOfType("model.UserGrant"), mock.AnythingOfType("time.Time")).
		Run(func(args mock.Arguments) { stored = args.Get(1).(model.UserGrant) }).
		Return(nil)

	// Act
	err := s.grantSvc.Grant(s.ctx, operator, subject, "order:export", nil, "临时项目需要")

	// Assert
	s.Require().NoError(err)
	s.Equal(subject, stored.SubjectID)
	s.Equal(perm.ID, stored.PermissionID)
	s.Equal(operator.SubjectID.String(), stored.CreatedBy)
	s.Nil(stored.ExpiresAt)
}

func (s *GrantServiceSuite) TestGrant_WithFutureExpiry_Created() {
	// Arrange
	permsByCode := s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	perm := permsByCode["order:export"]
	s.perms.On("FindByCode", mock.Anything, "order:export").Return(&perm, nil)
	s.expectGrantorHolds("order:export")
	s.grants.On("Grant", mock.Anything, mock.AnythingOfType("model.UserGrant"), mock.AnythingOfType("time.Time")).
		Return(nil)
	expiry := time.Now().UTC().Add(24 * time.Hour)

	// Act
	err := s.grantSvc.Grant(s.ctx, operator, subject, "order:export", &expiry, "")

	// Assert
	s.Require().NoError(err)
}

func (s *GrantServiceSuite) TestGrant_PastExpiry_Rejected() {
	// Arrange：到期时间校验先于授权者约束，无需配置持权期望。
	permsByCode := s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	perm := permsByCode["order:export"]
	s.perms.On("FindByCode", mock.Anything, "order:export").Return(&perm, nil)
	past := time.Now().UTC().Add(-time.Hour)

	// Act
	err := s.grantSvc.Grant(s.ctx, operator, subject, "order:export", &past, "")

	// Assert
	s.ErrorIs(err, core.ErrInvalidGrantExpiry)
}

func (s *GrantServiceSuite) TestGrant_UnregisteredCode_Rejected() {
	// Act
	err := s.grantSvc.Grant(s.ctx, operator, subject, "typo:code", nil, "")

	// Assert
	s.ErrorIs(err, core.ErrPermissionNotFound)
}

func (s *GrantServiceSuite) TestGrant_DisabledPermission_Rejected() {
	// Arrange
	s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	disabled := model.Permission{ID: 100, Code: "order:export", Status: model.PermissionStatusDisabled}
	s.perms.On("FindByCode", mock.Anything, "order:export").Return(&disabled, nil)

	// Act
	err := s.grantSvc.Grant(s.ctx, operator, subject, "order:export", nil, "")

	// Assert
	s.ErrorIs(err, core.ErrPermissionDisabled)
}

func (s *GrantServiceSuite) TestGrant_GrantorLacks_Rejected() {
	// Arrange
	permsByCode := s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	perm := permsByCode["order:export"]
	s.perms.On("FindByCode", mock.Anything, "order:export").Return(&perm, nil)
	s.expectGrantorHolds("user:list")

	// Act
	err := s.grantSvc.Grant(s.ctx, operator, subject, "order:export", nil, "")

	// Assert
	s.ErrorIs(err, core.ErrGrantorPermissionDenied)
}

func (s *GrantServiceSuite) TestRevoke_ActiveGrant_Revoked() {
	// Arrange
	permsByCode := s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	perm := permsByCode["order:export"]
	s.perms.On("FindByCode", mock.Anything, "order:export").Return(&perm, nil)
	s.grants.On("Revoke", mock.Anything, subject, perm.ID, operator.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return(int64(1), nil)

	// Act
	err := s.grantSvc.Revoke(s.ctx, operator, subject, "order:export")

	// Assert
	s.Require().NoError(err)
}

func (s *GrantServiceSuite) TestRevoke_NoActiveGrant_NotFound() {
	// Arrange
	permsByCode := s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	perm := permsByCode["order:export"]
	s.perms.On("FindByCode", mock.Anything, "order:export").Return(&perm, nil)
	s.grants.On("Revoke", mock.Anything, subject, perm.ID, operator.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return(int64(0), nil)

	// Act
	err := s.grantSvc.Revoke(s.ctx, operator, subject, "order:export")

	// Assert
	s.ErrorIs(err, core.ErrGrantNotFound)
}
