# Changelog

本项目的所有显著变更记录在此。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)（pre-1.0 阶段
`0.x`：次版本号递增代表功能性变更，可能包含不兼容的 API 调整）。

## [Unreleased]

### Changed（Breaking，pre-1.0 收口）

- `repository/` 迁移至 `internal/repository/`：以 Go 语言机制强制 §3.4
  "Repository 接口 v1 保持内部"的冻结决策（外部无法导入实现）；
  `App.PermissionsRepository` / `App.ReplaceRepositories` 保留导出，
  仅供库内模块（modules/*）装配使用
- `registry.Sync` 重构为 `registry.Diff`（纯函数，返回 `SyncPlan` 差量计划）+
  仓储 `ApplySync` 应用：registry 不再依赖存储接口，依赖方向修正为
  repository → registry；Diff 可纯函数表驱动测试
- 删除 `middleware/` 骨架包：适配器自包含规则（§3.3 逃生舱）使其永远没有
  库内使用方；自定义集成（如 gRPC）出现真实需求时再随用例编写

### Added

- `make cover-integration`：单元 + 集成合并覆盖率（库代码口径，当前 70.4%，
  消除"集成不计入"导致的覆盖率失真）；CI 增加 `make mocks-check`
  （生成代码与接口定义一致性校验）；App 装配级单测

### Fixed

- 并发创建同 code 角色的"先查后插"竞态：唯一键冲突现在映射为
  `ErrRoleCodeExists`（base/tenant 双仓储翻译 1062 → 内部哨兵）
- `SetPermissions` 差量事务增加死锁有界重试（与 Grant 同语义）
- 租户超管种子并发幂等（INSERT IGNORE）
- subject 大小写语义文档化（README 缓存章节）

- §6.5 审计发现（两层修复）：
  1. 仓储层 `NearestGrantExpiry` 用 `*time.Time` 扫描 `MIN(expires_at)`，
     空集 NULL 产生 "unsupported Scan" 错误——"无到期授权"与基础设施故障
     不可区分；改用 `sql.NullTime`（base 与 tenant 双实现）
  2. 授权层：到期时间读取失败时不再按"永久"写缓存（丢失 TTL 上限，
     临时授权可能在到期后被缓存放行至整个 TTL 结束），改为跳过写缓存
     并附回归测试

- 并发授权在 REPEATABLE READ 下因唯一索引间隙锁死锁（MySQL 1213）：
  Grant 事务增加有界重试（base/tenant 双实现；并发压力测试在 CI 捕获）
- CI 共享 runner 上性能基线偶发超时：命中路径阈值按环境放宽
  （本地 / RBAC_TEST_PERF_STRICT=1 保持 1ms，CI 放宽到 10ms 捕获数量级回归）
- release workflow 的发布正文经 shell 变量展开吞掉反引号代码段：
  改用 --notes-file 传递

## [0.4.0] - 2026-11-05

Phase 4：稳定性与生态（设计文档 §8）。

### Added

- 适配器多租户支持：`ginadapter.WithTenantResolver` /
  `httpadapter.WithTenantResolver`——受保护请求先解析租户再授权，
  租户缺失 fail closed（§2.9）
- datascope 的 `ResolveDataScope` 在租户部署下按授权域解析
- 接入示例：`examples/gin-redis`（Redis 缓存 + 观测）、
  `examples/gin-tenant`（多租户 + 菜单 + 数据范围全链路）
- godoc 示例（根包 / gin 适配器）与 `core` 包文档
- 测试补全：并发授权变更压力（-race）、§6.4 主从延迟边界文档化测试、
  §9.3 安全套件（含 Redis 故障矩阵）
- MySQL 8.4（LTS）进入 CI 集成矩阵；5.7 评估结论：
  不支持（`docs/db-compatibility.md`）
- 发布流程：tag 触发的 release workflow（`.github/workflows/release.yml`）

### Fixed

- datascope 误用 v1 语义的 `AuthorizationContext.Validate` 导致租户部署下
  解析被拒；该语义保留在 Validate（向后兼容），租户判断归授权服务策略

### 项目定名

pkg.go.dev 查重（§1/Phase 4）：已存在
[github.com/crmspy/go-rbac](https://pkg.go.dev/github.com/crmspy/go-rbac) 与
[github.com/DoWithLogic/go-rbac](https://github.com/DoWithLogic/go-rbac)，
但 Go 生态以 import path 为唯一键，`github.com/animacaeli/go-rbac` 无冲突；
两者均为小型库，未占据"go-rbac"事实标准位（该位置是 gorbac/Casbin）。
**结论：保留 go-rbac。**

## [0.3.0] - 2026-11-05

Phase 3：高级权限模块（设计文档 §8）。

### Added

- **Menu 模块**（§2.7）：菜单表迁移；代码声明式 `Declare`（幂等）；
  权限可选关联（OR 语义）；`ResolveVisibleMenus` 按主体解析可见树
- **DataScope 模块**（§2.8）：四种枚举范围、多角色取最宽合并、
  未配置默认 SELF（deny-by-default）、超管恒 ALL
- **Multi-Tenant 模块**（§2.9）：§5.5 迁移契约（加列 → 回填 → 重建三唯一键）
  及其验收测试（升级/全新双路径）；租户隔离仓储（ctx 授权域过滤，
  缺失 fail closed）；跨租户角色引用结构性拒绝；平台/租户超管边界；
  缓存 key 按授权域隔离；`SeedSuperAdminInTenant` 租户超管种子
- **core 租户策略**：`ErrTenantRequired`（启用租户后 TenantID 缺失即
  fail closed）；失效操作按 ctx 授权域递增版本/epoch
- **adapter/http**：net/http 标准库零依赖适配器
- 评估文档 `docs/phase3-evaluation.md`：CUSTOM 数据范围与组织架构接口
  （含 DepartmentResolver 形状与触发条件）、Outbox（维持 §6.7 延后定位）

### Fixed

- 失效键硬编码 default 域导致的租户缓存不失效（撤销即时生效用例暴露）
- menu/datascope upsert 未翻译 `gorm.ErrRecordNotFound`

## [0.2.0] - 2026-11-05

Phase 2：缓存与管理能力（设计文档 §6/§8）。

### Added

- **权限缓存一致性机制**（§6）：版本号 + 全局 epoch 两级失效
  （生成键 `perm:v{epoch<<32|version}`，与 §6.1 key 形状一致）；
  §6.2 不变性以代码强制（提交后递增）；写前复核丢弃重走；singleflight
  击穿防护；超管哨兵缓存（命中路径零 DB 查询）；§6.5 临时授权 TTL 上限
- **cache/redis**：Redis 适配器（GetInt/Incr、JSON 值、故障语义 §6.6）
- `PermissionCache` 接口扩展 `GetInt`/`Incr`
- **PermissionService**：权限启停（§6.3 权限禁用 → INCR epoch）
- **Audit 模块**：core.EventBus + 11 种事件 → `rbac_audit_logs`，
  Strict（默认）/LogOnly 失败策略，查询服务
- **Template 模块**：Snapshot/Copy 角色模板，注册期 fail fast
- 批量操作（一用户多角色 / 一角色多用户）、`core.CountingMetrics`
- §9.4 性能基线全部达标并进入测试：命中路径 P99 < 1ms、冷聚合 < 50ms、
  1k 用户批量失效 < 100ms、500 权限幂等同步 < 2s
- §6.3 失效矩阵在真实 Redis+MySQL 的端到端验证

## [0.1.0] - 2026-11-04

Phase 1：核心 RBAC（设计文档 §8）。

### Added

- 五张核心表 GORM 模型与版本化 SQL 迁移（io/fs embed +
  schema_migrations，语句拆分器，Core → 模块注册顺序）
- 权限注册中心：格式校验（拒绝通配符）、幂等同步（含废弃标记）、
  内置 `rbac:*` 管理权限码
- 授权服务：角色并集 ∪ 额外授权、字面匹配、超管语义（恒真/空集合）、
  账号非活跃 403 哨兵、fail closed 全路径
- 管理服务：角色（内置保护、in-use 保护）、用户角色、额外授权
  （生命周期事务）、授权者持权约束（默认开启）
- Gin 中间件：Require/RequireAny/RequireAll、错误响应定制、
  启动期权限码交叉校验
- Module Registry、NoopCache、middleware 骨架、`examples/gin-basic`
- 单元测试（testify + mockery）与 MySQL 集成测试；工程骨架
  （Makefile、git hooks、CI：lint / 测试矩阵 / 集成 / govulncheck）
