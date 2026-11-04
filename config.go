package rbac

import (
	"log/slog"
	"time"

	"github.com/animacaeli/go-rbac/cache"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/registry"
	"gorm.io/gorm"
)

// config 由 Options 填充。零值不可直接使用，经 New 应用默认值。
type config struct {
	db              *gorm.DB
	cch             cache.PermissionCache
	reg             *registry.Registry
	statusChecker   core.SubjectStatusChecker
	logger          *slog.Logger
	metrics         core.Metrics
	modules         []Module
	grantorMustHold bool
	cacheTTL        time.Duration
}

// Option 是 rbac.New 的配置项（§4.1）。
type Option func(*config)

// WithDB 注入 GORM 数据库句柄（必需）。DSN 建议
// parseTime=true&loc=UTC（§5.1：DATETIME(3) + 应用层 UTC）。
func WithDB(db *gorm.DB) Option { return func(c *config) { c.db = db } }

// WithCache 注入权限缓存实现（可选，默认 NoopCache）。
// v1 内置仅 NoopCache；Redis 实现于 Phase 2 提供。
func WithCache(cch cache.PermissionCache) Option { return func(c *config) { c.cch = cch } }

// WithPermissionRegistry 注入业务声明的权限注册中心（可选，默认空注册中心；
// 内置 rbac:* 管理权限码总是自动并入）。
func WithPermissionRegistry(reg *registry.Registry) Option {
	return func(c *config) { c.reg = reg }
}

// WithSubjectStatusChecker 注入账号状态检查器（可选）。未注入时跳过状态检查。
func WithSubjectStatusChecker(checker core.SubjectStatusChecker) Option {
	return func(c *config) { c.statusChecker = checker }
}

// WithLogger 注入结构化日志（可选，默认 slog.Default()）。
func WithLogger(l *slog.Logger) Option { return func(c *config) { c.logger = l } }

// WithMetrics 注入观测实现（可选，默认 NoopMetrics）。
func WithMetrics(m core.Metrics) Option { return func(c *config) { c.metrics = m } }

// WithModules 注册扩展模块（可选）。模块按注册顺序参与迁移执行（§3.3）。
func WithModules(mods ...Module) Option {
	return func(c *config) { c.modules = append(c.modules, mods...) }
}

// WithGrantorConstraint 配置"授权者必须持有拟授予权限"约束（§2.2）。
// 默认开启；传入 false 关闭，用于"权限管理员不需要持有全部业务权限"的场景。
func WithGrantorConstraint(enabled bool) Option {
	return func(c *config) { c.grantorMustHold = enabled }
}

// WithCacheTTL 配置权限缓存 TTL 上限（可选，默认 5 分钟）。
// 实际 TTL 始终不超过主体最近一条临时授权的到期时间（§6.5）。
func WithCacheTTL(d time.Duration) Option { return func(c *config) { c.cacheTTL = d } }
