package registry_test

import (
	"context"
	"testing"

	"github.com/animacaeli/go-rbac/model"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/animacaeli/go-rbac/repository"
	repositorymocks "github.com/animacaeli/go-rbac/test/mocks/repository"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type SyncSuite struct {
	suite.Suite
	ctx       context.Context
	permsMock *repositorymocks.MockPermissionRepo
	registry  *registry.Registry
}

func (s *SyncSuite) SetupTest() {
	s.ctx = context.Background()
	s.permsMock = repositorymocks.NewMockPermissionRepo(s.T())
	s.registry = registry.NewRegistry()
}

func TestSyncSuite(t *testing.T) { suite.Run(t, new(SyncSuite)) }

// expectDBPermissions 模拟数据库现状。
func (s *SyncSuite) expectDBPermissions(existing []model.Permission) {
	s.permsMock.On("ListAll", mock.Anything).Return(existing, nil).Maybe()
}

// captureSync 捕获 ApplySync 收到的差量。
func (s *SyncSuite) captureSync() *repository.PermissionSync {
	var captured repository.PermissionSync
	s.permsMock.On("ApplySync", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			captured = args.Get(1).(repository.PermissionSync)
		}).
		Return(nil).
		Maybe()
	return &captured
}

func (s *SyncSuite) TestSync_NewPermission_Inserted() {
	// Arrange
	s.expectDBPermissions(nil)
	s.Require().NoError(s.registry.Register(registry.New("user:list", "用户列表", "用户管理")))
	captured := s.captureSync()

	// Act
	result, err := registry.Sync(s.ctx, s.registry, s.permsMock)

	// Assert
	s.Require().NoError(err)
	s.Equal(1, result.Created)
	s.Equal(0, result.Deprecated)
	s.Require().Len(captured.Inserts, 1)
	s.Equal("user:list", captured.Inserts[0].Code)
	s.Equal(model.PermissionStatusEnabled, captured.Inserts[0].Status)
}

func (s *SyncSuite) TestSync_MetadataChange_Updated() {
	// Arrange
	s.expectDBPermissions([]model.Permission{
		{ID: 7, Code: "user:list", Name: "旧名字", Module: "用户管理", Status: model.PermissionStatusEnabled},
	})
	s.Require().NoError(s.registry.Register(registry.New("user:list", "新名字", "用户管理2")))
	captured := s.captureSync()

	// Act
	result, err := registry.Sync(s.ctx, s.registry, s.permsMock)

	// Assert
	s.Require().NoError(err)
	s.Equal(0, result.Created)
	s.Equal(1, result.Updated)
	s.Require().Len(captured.MetadataUpdates, 1)
	s.Equal(uint64(7), captured.MetadataUpdates[0].ID)
	s.Equal("新名字", captured.MetadataUpdates[0].Name)
}

func (s *SyncSuite) TestSync_DeprecatedPermission_Reactivated() {
	// Arrange
	s.expectDBPermissions([]model.Permission{
		{ID: 9, Code: "user:list", Name: "用户列表", Module: "用户管理", Status: model.PermissionStatusDeprecated},
	})
	s.Require().NoError(s.registry.Register(registry.New("user:list", "用户列表", "用户管理")))
	captured := s.captureSync()

	// Act
	result, err := registry.Sync(s.ctx, s.registry, s.permsMock)

	// Assert
	s.Require().NoError(err)
	s.Equal(1, result.Reactivated)
	s.Equal([]uint64{9}, captured.ReactivateIDs)
}

func (s *SyncSuite) TestSync_OrphanEnabledPermission_Deprecated() {
	// Arrange
	s.expectDBPermissions([]model.Permission{
		{ID: 3, Code: "legacy:action", Name: "遗留", Module: "legacy", Status: model.PermissionStatusEnabled},
		{ID: 4, Code: "manual:off", Name: "手动禁用", Module: "manual", Status: model.PermissionStatusDisabled},
		{ID: 5, Code: "old:gone", Name: "已废弃", Module: "old", Status: model.PermissionStatusDeprecated},
	})
	s.Require().NoError(s.registry.Register(registry.New("user:list", "用户列表", "用户管理")))
	captured := s.captureSync()

	// Act
	result, err := registry.Sync(s.ctx, s.registry, s.permsMock)

	// Assert
	s.Require().NoError(err)
	s.Equal(1, result.Deprecated)
	// 仅"启用中"的孤儿被废弃；手动禁用与已废弃不动。
	s.Equal([]uint64{3}, captured.DeprecateIDs)
}

func (s *SyncSuite) TestSync_NoChanges_EmptyDiffApplied() {
	// Arrange
	s.expectDBPermissions([]model.Permission{
		{ID: 1, Code: "user:list", Name: "用户列表", Module: "用户管理", Status: model.PermissionStatusEnabled},
	})
	s.Require().NoError(s.registry.Register(registry.New("user:list", "用户列表", "用户管理")))
	captured := s.captureSync()

	// Act
	result, err := registry.Sync(s.ctx, s.registry, s.permsMock)

	// Assert
	s.Require().NoError(err)
	s.Equal(registry.SyncResult{}, result)
	s.Empty(captured.Inserts)
	s.Empty(captured.MetadataUpdates)
	s.Empty(captured.ReactivateIDs)
	s.Empty(captured.DeprecateIDs)
}
