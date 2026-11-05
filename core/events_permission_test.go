package core_test

import (
	"testing"

	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
	cachemocks "github.com/animacaeli/go-rbac/test/mocks/cache"
	coremocks "github.com/animacaeli/go-rbac/test/mocks/core"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// EventsSuite 验证授权变更事件的分发（§2.10）：数据库提交 + 失效成功后写入；
// 事件失败向上传播（§6.7 整体报错，不出现半成功状态）。
type EventsSuite struct {
	serviceHarness
	sinkMock *coremocks.MockEventSink
}

func (s *EventsSuite) SetupTest() {
	s.setupHarness(true)
	s.sinkMock = coremocks.NewMockEventSink(s.T())
	bus := core.NewEventBus()
	bus.SetSink(s.sinkMock)
	s.deps.Events = bus
	// 用注入事件总线后的 deps 重建被测服务。
	s.roleSvc = core.NewRoleService(s.deps)
	s.userRoleSvc = core.NewUserRoleService(s.deps)
	s.grantSvc = core.NewGrantService(s.deps)
}

func TestEventsSuite(t *testing.T) { suite.Run(t, new(EventsSuite)) }

func (s *EventsSuite) TestRoleCreate_EventRecorded() {
	// Arrange
	s.roles.On("FindByCode", mock.Anything, "ops").Return(nil, repository.ErrRecordNotFound)
	s.roles.On("Create", mock.Anything, mock.AnythingOfType("*model.Role")).Return(nil)
	s.sinkMock.On("RecordEvent", mock.Anything, mock.AnythingOfType("core.Event")).
		Run(func(args mock.Arguments) {
			e := args.Get(1).(core.Event)
			s.Equal(core.EventRoleCreated, e.Type)
			s.Equal(operator.SubjectID, e.Operator)
			s.Equal("ops", e.Target)
		}).
		Return(nil)

	// Act
	_, err := s.roleSvc.Create(s.ctx, operator, "ops", "运营", "")

	// Assert
	s.Require().NoError(err)
}

func (s *EventsSuite) TestGrantFlow_EventsRecordedAfterCommitAndInvalidation() {
	// Arrange
	permsByCode := s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	perm := permsByCode["order:export"]
	s.perms.On("FindByCode", mock.Anything, "order:export").Return(&perm, nil)
	s.expectGrantorHolds("order:export")
	s.grants.On("Grant", mock.Anything, mock.AnythingOfType("model.UserGrant"), mock.AnythingOfType("time.Time")).
		Return(nil)
	s.sinkMock.On("RecordEvent", mock.Anything, mock.AnythingOfType("core.Event")).
		Run(func(args mock.Arguments) {
			e := args.Get(1).(core.Event)
			s.Equal(core.EventUserGranted, e.Type)
			s.Equal(subject, e.Target)
		}).
		Return(nil).Once()
	s.grants.On("Revoke", mock.Anything, subject, perm.ID, operator.SubjectID.String(), mock.AnythingOfType("time.Time")).
		Return(int64(1), nil)
	s.sinkMock.On("RecordEvent", mock.Anything, mock.AnythingOfType("core.Event")).
		Run(func(args mock.Arguments) {
			e := args.Get(1).(core.Event)
			s.Equal(core.EventGrantRevoked, e.Type)
		}).
		Return(nil).Once()

	// Act
	s.Require().NoError(s.grantSvc.Grant(s.ctx, operator, subject, "order:export", nil, "临时"))
	s.Require().NoError(s.grantSvc.Revoke(s.ctx, operator, subject, "order:export"))
}

func (s *EventsSuite) TestEventSinkError_PropagatesAsOperationFailure() {
	// Arrange：事件写入失败 → 操作整体报错（数据库已提交，调用方按 §6.7 语义处理）。
	s.roles.On("FindByCode", mock.Anything, "ops").Return(nil, repository.ErrRecordNotFound)
	s.roles.On("Create", mock.Anything, mock.AnythingOfType("*model.Role")).Return(nil)
	s.sinkMock.On("RecordEvent", mock.Anything, mock.AnythingOfType("core.Event")).
		Return(errAuditDown)

	// Act
	_, err := s.roleSvc.Create(s.ctx, operator, "ops", "运营", "")

	// Assert
	s.Require().Error(err)
}

type auditDownError struct{}

func (auditDownError) Error() string { return "audit storage down" }

var errAuditDown = auditDownError{}

// ---- PermissionService（§6.3 epoch 失效入口） ----

type PermissionServiceSuite struct {
	serviceHarness
	permSvc *core.PermissionService
}

func (s *PermissionServiceSuite) SetupTest() {
	s.authzCacheMock = cachemocks.NewMockPermissionCache(s.T())
	s.setupHarness(true)
	s.permSvc = core.NewPermissionService(s.deps)
}

func TestPermissionServiceSuite(t *testing.T) { suite.Run(t, new(PermissionServiceSuite)) }

func (s *PermissionServiceSuite) TestSetStatus_Disable_IncrementsEpoch() {
	// Arrange
	s.mustRegisterPermissions(registry.New("order:export", "导出订单", "订单管理"))
	enabled := model.Permission{ID: 100, Code: "order:export", Status: model.PermissionStatusEnabled}
	s.perms.On("FindByCode", mock.Anything, "order:export").Return(&enabled, nil)
	s.perms.On("SetStatus", mock.Anything, uint64(100), model.PermissionStatusDisabled).Return(nil)
	// §6.3 失效矩阵：权限禁用 → INCR 全局 epoch。
	s.cchSyncExpect("rbac:default:epoch", "default:epoch", int64(1))

	// Act
	err := s.permSvc.SetStatus(s.ctx, operator, "order:export", model.PermissionStatusDisabled)

	// Assert
	s.Require().NoError(err)
}

func (s *PermissionServiceSuite) TestSetStatus_Idempotent_NoEpochBump() {
	// Arrange：状态未变化 → 无写库、无失效。
	enabled := model.Permission{ID: 100, Code: "order:export", Status: model.PermissionStatusEnabled}
	s.perms.On("FindByCode", mock.Anything, "order:export").Return(&enabled, nil)

	// Act
	err := s.permSvc.SetStatus(s.ctx, operator, "order:export", model.PermissionStatusEnabled)

	// Assert
	s.Require().NoError(err)
}

func (s *PermissionServiceSuite) TestSetStatus_UnknownCode_NotFound() {
	// Arrange
	s.perms.On("FindByCode", mock.Anything, "ghost:code").Return(nil, repository.ErrRecordNotFound)

	// Act
	err := s.permSvc.SetStatus(s.ctx, operator, "ghost:code", model.PermissionStatusDisabled)

	// Assert
	s.ErrorIs(err, core.ErrPermissionNotFound)
}

func (s *PermissionServiceSuite) TestSetStatus_InvalidStatus_Rejected() {
	// Arrange：状态校验先于仓储访问，无需注册仓储期望。

	// Act
	err := s.permSvc.SetStatus(s.ctx, operator, "order:export", 9)

	// Assert
	s.Require().Error(err)
}
