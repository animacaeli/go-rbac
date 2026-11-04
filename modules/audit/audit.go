// Package audit 实现授权变更审计模块（§2.10）：以 core.EventSink 身份接收
// 授权变更事件并落库到 rbac_audit_logs，同时提供查询服务。
//
// 模块职责边界：
//   - 不影响基础授权判断的可用性——但授权变更事件写入失败时默认使操作
//     整体报错（Strict 策略，§2.10 "明确审计失败的处理策略" + §6.7）
//   - 可选 LogOnly 策略：审计失败仅记日志，不阻断管理操作（接受审计缺口）
//   - 关联关系历史的唯一归属（§5.3）
//
// 用法：
//
//	app, _ := rbac.New(
//	    rbac.WithDB(db),
//	    rbac.WithModules(audit.New()),          // 默认 Strict
//	    // rbac.WithModules(audit.New(audit.WithLogOnly())),  // 审计降级为日志
//	)
//	// app.Migrate 会自动包含 audit 模块迁移（Core → 模块注册顺序）
//	logs, _ := app.Module(...)  // 或自行持有 audit.New() 返回的实例调用 Query
package audit

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/core"
	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var auditFS embed.FS

// FailPolicy 是审计失败的处理策略（§2.10）。
type FailPolicy int

const (
	// PolicyStrict 审计失败 → 授权变更操作整体报错（默认）。
	PolicyStrict FailPolicy = iota
	// PolicyLogOnly 审计失败 → 记录日志并放行（接受审计缺口，换取管理可用性）。
	PolicyLogOnly
)

// Module 是 Audit 模块（实现 rbac.Module 与 core.EventSink）。
type Module struct {
	policy FailPolicy
	logger *slog.Logger
	db     *gorm.DB
}

var (
	_ rbac.Module    = (*Module)(nil)
	_ core.EventSink = (*Module)(nil)
)

// Option 定制模块行为。
type Option func(*Module)

// WithLogOnly 将审计失败策略设为"仅记日志"。
func WithLogOnly() Option { return func(m *Module) { m.policy = PolicyLogOnly } }

// WithLogger 注入日志器（默认 slog.Default()）。
func WithLogger(l *slog.Logger) Option {
	return func(m *Module) { m.logger = l }
}

// New 构造 Audit 模块。
func New(opts ...Option) *Module {
	m := &Module{policy: PolicyStrict, logger: slog.Default()}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Name 返回模块名（迁移 Module 键）。
func (m *Module) Name() string { return "audit" }

// Register 注入事件实现并捕获数据库句柄。只做注册，不触库（§3.3）。
func (m *Module) Register(app *rbac.App) error {
	m.db = app.DB()
	app.SetEventSink(m)
	return nil
}

// Migrations 返回模块迁移（rbac_audit_logs，§5.6）。
func (m *Module) Migrations() []rbac.Migration {
	data, err := auditFS.ReadFile("migrations/0001_audit_logs.sql")
	if err != nil {
		panic(fmt.Sprintf("rbac/modules/audit: read embedded migration: %v", err))
	}
	return []rbac.Migration{
		{Module: m.Name(), Version: "0001", Name: "audit_logs", SQL: string(data)},
	}
}

// AuditLog 对应表 rbac_audit_logs。
type AuditLog struct {
	ID         uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	EventType  string    `gorm:"column:event_type;size:64;not null"`
	OperatorID string    `gorm:"column:operator_id;size:128;not null"`
	TenantID   string    `gorm:"column:tenant_id;size:64;not null;default:''"`
	Target     string    `gorm:"column:target;size:255;not null;default:''"`
	Detail     string    `gorm:"column:detail;type:text"`
	CreatedAt  time.Time `gorm:"column:created_at;autoCreateTime:milli"`
}

// TableName 返回表名。
func (AuditLog) TableName() string { return "rbac_audit_logs" }

// RecordEvent 实现 core.EventSink：事件落库。
func (m *Module) RecordEvent(ctx context.Context, e core.Event) error {
	detail := ""
	if len(e.Detail) > 0 {
		if raw, err := json.Marshal(e.Detail); err == nil {
			detail = string(raw)
		}
	}
	log := AuditLog{
		EventType:  string(e.Type),
		OperatorID: e.Operator.String(),
		TenantID:   e.TenantID,
		Target:     e.Target,
		Detail:     detail,
		CreatedAt:  e.At,
	}
	if err := m.db.WithContext(ctx).Create(&log).Error; err != nil {
		wrapped := fmt.Errorf("rbac/modules/audit: record event %s: %w", e.Type, err)
		if m.policy == PolicyLogOnly {
			m.logger.Error("audit record failed (log-only policy)", "err", wrapped, "event", e.Type)
			return nil
		}
		return wrapped
	}
	return nil
}

// Filter 是审计查询条件。
type Filter struct {
	Operator string    // 精确匹配操作人
	Type     string    // 精确匹配事件类型
	Subject  string    // target 精确匹配（被操作对象）
	Since    time.Time // created_at >=
	Until    time.Time // created_at <（零值忽略）
	Offset   int
	Limit    int // <=0 默认 100，上限 1000
}

// Query 审计查询服务。
type Query struct {
	db *gorm.DB
}

// NewQuery 以模块实例构造查询服务（需已 Register）。
func NewQuery(m *Module) *Query { return &Query{db: m.db} }

// List 按条件查询审计记录，按时间倒序。
func (q *Query) List(ctx context.Context, f Filter) ([]AuditLog, error) {
	query := q.db.WithContext(ctx).Model(&AuditLog{})
	if f.Operator != "" {
		query = query.Where("operator_id = ?", f.Operator)
	}
	if f.Type != "" {
		query = query.Where("event_type = ?", f.Type)
	}
	if f.Subject != "" {
		query = query.Where("target = ?", f.Subject)
	}
	if !f.Since.IsZero() {
		query = query.Where("created_at >= ?", f.Since)
	}
	if !f.Until.IsZero() {
		query = query.Where("created_at < ?", f.Until)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	var logs []AuditLog
	if err := query.Order("id DESC").Offset(f.Offset).Limit(limit).Find(&logs).Error; err != nil {
		return nil, fmt.Errorf("rbac/modules/audit: list: %w", err)
	}
	return logs, nil
}
