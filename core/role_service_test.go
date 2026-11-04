package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/animacaeli/go-rbac/cache"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/animacaeli/go-rbac/repository"
	repositorymocks "github.com/animacaeli/go-rbac/test/mocks/repository"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// serviceHarness 汇聚三个管理服务测试套件共用的装配逻辑。
type serviceHarness struct {
	suite.Suite
	ctx         context.Context
	roles       *repositorymocks.MockRoleRepo
	perms       *repositorymocks.MockPermissionRepo
	userRoles   *repositorymocks.MockUserRoleRepo
	rolePerms   *repositorymocks.MockRolePermissionRepo
	grants      *repositorymocks.MockUserGrantRepo
	authzRepo   *repositorymocks.MockAuthorizationRepo
	reg         *registry.Registry
	deps        core.ServiceDeps
	roleSvc     *core.RoleService
	userRoleSvc *core.UserRoleService
	grantSvc    *core.GrantService
}

var (
	// operator 是管理操作者（授权者约束的检查对象）。
	operator = core.AuthorizationContext{SubjectID: "admin-1"}
	// subject 是被授权的普通用户。
	subject = "10001"
)

func (h *serviceHarness) setupHarness(grantorMustHold bool) {
	h.ctx = context.Background()
	h.roles = repositorymocks.NewMockRoleRepo(h.T())
	h.perms = repositorymocks.NewMockPermissionRepo(h.T())
	h.userRoles = repositorymocks.NewMockUserRoleRepo(h.T())
	h.rolePerms = repositorymocks.NewMockRolePermissionRepo(h.T())
	h.grants = repositorymocks.NewMockUserGrantRepo(h.T())
	h.authzRepo = repositorymocks.NewMockAuthorizationRepo(h.T())
	h.reg = registry.NewRegistry()

	// 授权服务用真实实现 + mock 聚合仓储 + NoopCache：
	// 服务层经 authorizer 做持权检查，路径为 HasBuiltinSuperAdminRole → Effective*。
	authorizer := core.NewAuthorizationService(h.authzRepo, cache.NoopCache{}, nil, core.NoopMetrics{}, time.Minute)

	h.deps = core.ServiceDeps{
		Roles:           h.roles,
		Permissions:     h.perms,
		UserRoles:       h.userRoles,
		RolePermissions: h.rolePerms,
		Grants:          h.grants,
		Registry:        h.reg,
		Authorizer:      authorizer,
		GrantorMustHold: grantorMustHold,
	}
	h.roleSvc = core.NewRoleService(h.deps)
	h.userRoleSvc = core.NewUserRoleService(h.deps)
	h.grantSvc = core.NewGrantService(h.deps)
}

// mustRegisterPermissions 将权限码注册进 Registry（启用状态、给定 ID）。
func (h *serviceHarness) mustRegisterPermissions(defs ...registry.PermissionDef) map[string]model.Permission {
	out := make(map[string]model.Permission, len(defs))
	for _, def := range defs {
		h.Require().NoError(h.reg.Register(def))
		out[def.Code] = model.Permission{
			ID:     uint64(len(out) + 100),
			Code:   def.Code,
			Name:   def.Name,
			Module: def.Module,
			Status: model.PermissionStatusEnabled,
		}
	}
	return out
}

// expectGrantorHolds 配置 operator 持有给定权限（非超管）。
func (h *serviceHarness) expectGrantorHolds(codes ...string) {
	h.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, operator.SubjectID.String()).
		Return(false, nil)
	h.authzRepo.On("EffectiveRolePermissions", mock.Anything, operator.SubjectID.String()).
		Return(codes, nil)
	h.authzRepo.On("EffectiveGrantPermissions", mock.Anything, operator.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return(nil, nil)
	h.authzRepo.On("NearestGrantExpiry", mock.Anything, operator.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return(nil, nil)
}

// expectGrantorIsSuper 配置 operator 为超级管理员（持权约束豁免）。
// 注意：不注册 Effective* 期望——超管路径不得触达聚合查询。
func (h *serviceHarness) expectGrantorIsSuper() {
	h.authzRepo.On("HasBuiltinSuperAdminRole", mock.Anything, operator.SubjectID.String()).
		Return(true, nil)
}

// ---- RoleService ----

type RoleServiceSuite struct {
	serviceHarness
}

func (s *RoleServiceSuite) SetupTest() { s.setupHarness(true) }

func TestRoleServiceSuite(t *testing.T) { suite.Run(t, new(RoleServiceSuite)) }

func (s *RoleServiceSuite) TestCreate_ValidRole_Created() {
	// Arrange
	s.roles.On("FindByCode", mock.Anything, "ops").Return(nil, repository.ErrRecordNotFound)
	var created *model.Role
	s.roles.On("Create", mock.Anything, mock.AnythingOfType("*model.Role")).
		Run(func(args mock.Arguments) { created = args.Get(1).(*model.Role) }).
		Return(nil)

	// Act
	role, err := s.roleSvc.Create(s.ctx, operator, "ops", "运营专员", "运营日常")

	// Assert
	s.Require().NoError(err)
	s.Require().NotNil(created)
	s.Equal("ops", role.Code)
	s.Equal(model.RoleStatusEnabled, created.Status)
	s.False(created.IsBuiltin)
}

func (s *RoleServiceSuite) TestCreate_DuplicateCode_Rejected() {
	// Arrange
	s.roles.On("FindByCode", mock.Anything, "ops").
		Return(&model.Role{ID: 1, Code: "ops"}, nil)

	// Act
	_, err := s.roleSvc.Create(s.ctx, operator, "ops", "运营专员", "")

	// Assert
	s.ErrorIs(err, core.ErrRoleCodeExists)
}

func (s *RoleServiceSuite) TestCreate_InvalidCode_Rejected() {
	tests := []string{"", "  "}
	for _, code := range tests {
		s.Run("code_"+code, func() {
			// Act
			_, err := s.roleSvc.Create(s.ctx, operator, code, "名字", "")

			// Assert
			s.ErrorIs(err, core.ErrInvalidRoleCode)
		})
	}
}

func (s *RoleServiceSuite) TestUpdate_RoleNotFound_Rejected() {
	// Arrange
	s.roles.On("FindByID", mock.Anything, uint64(42)).Return(nil, repository.ErrRecordNotFound)

	// Act
	err := s.roleSvc.Update(s.ctx, operator, 42, "新名字", "")

	// Assert
	s.ErrorIs(err, core.ErrRoleNotFound)
}

func (s *RoleServiceSuite) TestSetStatus_BuiltinRole_Protected() {
	// Arrange
	builtin := &model.Role{ID: 1, Code: model.BuiltinSuperAdminRoleCode, IsBuiltin: true}
	s.roles.On("FindByID", mock.Anything, uint64(1)).Return(builtin, nil)

	// Act
	err := s.roleSvc.SetStatus(s.ctx, operator, 1, model.RoleStatusDisabled)

	// Assert
	s.ErrorIs(err, core.ErrBuiltinRoleProtected)
}

func (s *RoleServiceSuite) TestSetStatus_Disable_InvalidatesRoleSubjects() {
	// Arrange
	normal := &model.Role{ID: 2, Code: "ops", Status: model.RoleStatusEnabled}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	s.roles.On("SetStatus", mock.Anything, uint64(2), model.RoleStatusDisabled).Return(nil)
	s.userRoles.On("SubjectIDsOfRole", mock.Anything, uint64(2)).Return([]string{subject}, nil)

	// Act
	err := s.roleSvc.SetStatus(s.ctx, operator, 2, model.RoleStatusDisabled)

	// Assert：§6.3 角色禁用 → 批量失效关联用户（NoopCache 下为空操作，不报错）。
	s.Require().NoError(err)
}

func (s *RoleServiceSuite) TestDelete_BuiltinRole_Protected() {
	// Arrange
	builtin := &model.Role{ID: 1, Code: model.BuiltinSuperAdminRoleCode, IsBuiltin: true}
	s.roles.On("FindByID", mock.Anything, uint64(1)).Return(builtin, nil)

	// Act
	err := s.roleSvc.Delete(s.ctx, operator, 1)

	// Assert
	s.ErrorIs(err, core.ErrBuiltinRoleProtected)
}

func (s *RoleServiceSuite) TestDelete_RoleInUse_Rejected() {
	// Arrange
	normal := &model.Role{ID: 2, Code: "ops"}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	s.roles.On("CountUsers", mock.Anything, uint64(2)).Return(int64(3), nil)

	// Act
	err := s.roleSvc.Delete(s.ctx, operator, 2)

	// Assert
	s.ErrorIs(err, core.ErrRoleInUse)
}

func (s *RoleServiceSuite) TestDelete_UnusedRole_DeletedWithAssociations() {
	// Arrange
	normal := &model.Role{ID: 2, Code: "ops"}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	s.roles.On("CountUsers", mock.Anything, uint64(2)).Return(int64(0), nil)
	s.roles.On("DeleteWithAssociations", mock.Anything, uint64(2)).Return(nil)

	// Act
	err := s.roleSvc.Delete(s.ctx, operator, 2)

	// Assert
	s.Require().NoError(err)
}

func (s *RoleServiceSuite) TestSetPermissions_GrantorHolds_Replaced() {
	// Arrange
	permsByCode := s.mustRegisterPermissions(
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("order:export", "导出订单", "订单管理"),
	)
	normal := &model.Role{ID: 2, Code: "ops"}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	codes := []string{"user:list", "order:export"}
	s.perms.On("FindByCodes", mock.Anything, mock.Anything).
		Return([]model.Permission{permsByCode["user:list"], permsByCode["order:export"]}, nil)
	s.expectGrantorHolds(codes...)
	s.rolePerms.On("SetPermissions", mock.Anything, uint64(2),
		[]uint64{permsByCode["user:list"].ID, permsByCode["order:export"].ID}).
		Return(nil)
	s.userRoles.On("SubjectIDsOfRole", mock.Anything, uint64(2)).Return(nil, nil)

	// Act
	err := s.roleSvc.SetPermissions(s.ctx, operator, 2, codes)

	// Assert
	s.Require().NoError(err)
}

func (s *RoleServiceSuite) TestSetPermissions_GrantorLacks_Rejected() {
	// Arrange
	permsByCode := s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	normal := &model.Role{ID: 2, Code: "ops"}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	s.perms.On("FindByCodes", mock.Anything, mock.Anything).
		Return([]model.Permission{permsByCode["order:export"]}, nil)
	s.expectGrantorHolds("user:list") // operator 只持有 user:list，不持有 order:export

	// Act
	err := s.roleSvc.SetPermissions(s.ctx, operator, 2, []string{"order:export"})

	// Assert：§2.2 授权者必须持有拟授予权限。
	s.ErrorIs(err, core.ErrGrantorPermissionDenied)
}

func (s *RoleServiceSuite) TestSetPermissions_GrantorIsSuper_BypassConstraint() {
	// Arrange
	permsByCode := s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	normal := &model.Role{ID: 2, Code: "ops"}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	s.perms.On("FindByCodes", mock.Anything, mock.Anything).
		Return([]model.Permission{permsByCode["order:export"]}, nil)
	s.expectGrantorIsSuper() // Effective* 未注册：超管不得走聚合查询
	s.rolePerms.On("SetPermissions", mock.Anything, uint64(2), mock.Anything).Return(nil)
	s.userRoles.On("SubjectIDsOfRole", mock.Anything, uint64(2)).Return(nil, nil)

	// Act
	err := s.roleSvc.SetPermissions(s.ctx, operator, 2, []string{"order:export"})

	// Assert
	s.Require().NoError(err)
}

func (s *RoleServiceSuite) TestSetPermissions_UnregisteredCode_Rejected() {
	// Arrange
	normal := &model.Role{ID: 2, Code: "ops"}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)

	// Act
	err := s.roleSvc.SetPermissions(s.ctx, operator, 2, []string{"typo:code"})

	// Assert：§2.2 只能引用 Registry 已注册权限。
	s.ErrorIs(err, core.ErrPermissionNotFound)
}

func (s *RoleServiceSuite) TestSetPermissions_DisabledPermission_Rejected() {
	// Arrange
	s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	normal := &model.Role{ID: 2, Code: "ops"}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	disabled := model.Permission{ID: 100, Code: "order:export", Status: model.PermissionStatusDisabled}
	s.perms.On("FindByCodes", mock.Anything, mock.Anything).Return([]model.Permission{disabled}, nil)

	// Act
	err := s.roleSvc.SetPermissions(s.ctx, operator, 2, []string{"order:export"})

	// Assert
	s.ErrorIs(err, core.ErrPermissionDisabled)
}

func (s *RoleServiceSuite) TestSetPermissions_BuiltinRole_Protected() {
	// Arrange
	builtin := &model.Role{ID: 1, Code: model.BuiltinSuperAdminRoleCode, IsBuiltin: true}
	s.roles.On("FindByID", mock.Anything, uint64(1)).Return(builtin, nil)

	// Act
	err := s.roleSvc.SetPermissions(s.ctx, operator, 1, []string{"user:list"})

	// Assert
	s.ErrorIs(err, core.ErrBuiltinRoleProtected)
}

func (s *RoleServiceSuite) TestSetPermissions_ConstraintDisabled_GrantorNeedNotHold() {
	// Arrange —— 独立装配 GrantorMustHold=false。
	s.setupHarness(false)
	permsByCode := s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	normal := &model.Role{ID: 2, Code: "ops"}
	s.roles.On("FindByID", mock.Anything, uint64(2)).Return(normal, nil)
	s.perms.On("FindByCodes", mock.Anything, mock.Anything).
		Return([]model.Permission{permsByCode["order:export"]}, nil)
	// authzRepo 未注册任何期望：约束关闭时不做持权检查。
	s.rolePerms.On("SetPermissions", mock.Anything, uint64(2), mock.Anything).Return(nil)
	s.userRoles.On("SubjectIDsOfRole", mock.Anything, uint64(2)).Return(nil, nil)

	// Act
	err := s.roleSvc.SetPermissions(s.ctx, operator, 2, []string{"order:export"})

	// Assert
	s.Require().NoError(err)
}
