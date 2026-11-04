package core

import (
	"context"
	"sync"
	"time"
)

// EventType 是授权体系变更事件类型（§2.10）。审计模块是这些历史的唯一归属。
type EventType string

const (
	EventRoleCreated            EventType = "role.created"
	EventRoleUpdated            EventType = "role.updated"
	EventRoleDeleted            EventType = "role.deleted"
	EventRoleStatusChanged      EventType = "role.status_changed"
	EventRolePermissionsChanged EventType = "role.permissions_changed"
	EventUserRoleAssigned       EventType = "user_role.assigned"
	EventUserRoleRevoked        EventType = "user_role.revoked"
	EventUserGranted            EventType = "grant.created"
	EventGrantRevoked           EventType = "grant.revoked"
	EventPermissionsSynced      EventType = "permission.synced"
	EventPermissionStatusSet    EventType = "permission.status_set"
)

// Event 描述一次授权体系变更：操作人、目标对象、变更内容、时间（§2.10）。
type Event struct {
	Type     EventType
	Operator SubjectID
	TenantID string
	// Target 目标对象标识（角色 code、subject_id 等）。
	Target string
	// Detail 变更内容摘要（如权限码清单、状态前后值）。
	Detail map[string]string
	At     time.Time
}

// NewEvent 构造事件并填充时间。
func NewEvent(t EventType, operator AuthorizationContext, target string, detail map[string]string) Event {
	return Event{
		Type:     t,
		Operator: operator.SubjectID,
		TenantID: operator.TenantID,
		Target:   target,
		Detail:   detail,
		At:       time.Now().UTC(),
	}
}

// EventSink 消费授权变更事件（Audit 模块实现；业务项目也可自行注入）。
type EventSink interface {
	RecordEvent(ctx context.Context, e Event) error
}

// NoopEventSink 丢弃全部事件（未配置审计时的默认形态）。
type NoopEventSink struct{}

// RecordEvent 无操作。
func (NoopEventSink) RecordEvent(context.Context, Event) error { return nil }

// EventBus 是事件的分发点：服务层在数据库提交 + 缓存失效成功后写入；
// Audit 模块在注册时通过 rbac.App.SetEventSink 注入实现。
//
// 失败策略（§2.10）：Record 错误向上传播，管理接口整体报错——
// 与 §6.7 "无 Outbox 时以整体报错保证不出现半成功状态"一致。
type EventBus struct {
	mu   sync.RWMutex
	sink EventSink
}

// NewEventBus 创建未配置 sink 的事件总线（事件被丢弃）。
func NewEventBus() *EventBus {
	return &EventBus{sink: NoopEventSink{}}
}

// SetSink 替换事件实现。
func (b *EventBus) SetSink(sink EventSink) {
	if sink == nil {
		sink = NoopEventSink{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sink = sink
}

// Record 分发事件。
func (b *EventBus) Record(ctx context.Context, e Event) error {
	b.mu.RLock()
	sink := b.sink
	b.mu.RUnlock()
	return sink.RecordEvent(ctx, e)
}
