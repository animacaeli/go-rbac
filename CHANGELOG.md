# Changelog

本项目的所有显著变更记录在此。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)（pre-1.0 阶段
`0.x`：次版本号递增代表功能性变更，可能包含不兼容的 API 调整）。

## [Unreleased]

### Changed（Breaking，DB 权威版本号——外部审核第三轮 P0）

- **版本号权威来源从 Redis 迁移到数据库**（`rbac_counters` 表，迁移 0002）：
  授权变更与版本递增在同一事务提交；Redis 计数器降级为权威值的缓存副本
  （丢失/损坏 → DB 回填真实值，不存在重置碰撞；同步失败 → 删副本回退 DB，
  正确性不受影响）。**提交后失效失败不再产生旧权限放行窗口**——
  副本落后只影响缓存命中率，不影响正确性
- `PermissionCache` 接口：新增 `SetInt`，移除 `InitCounter`/`DeleteByPattern`
  （基线清洗协议随 DB 权威化整体删除）
- **角色级变更改用 epoch 原子失效**（P0-2）：权限分配/角色禁用/删除/权限
  禁用/同步一次递增全域 epoch，消除逐用户 fan-out 的部分成功窗口
  （1k 用户批量失效不再是热点，全域冷启动一次可接受）
- `Event` 增加 `ID`（幂等消费去重用）；`ErrInvalidationFailedAfterCommit` /
  `ErrAuditFailedAfterCommit` 文案去除"safe to retry"绝对承诺，
  README 增加按操作分级的重试语义表
- 审计策略语义澄清：Strict ≠ 事务性审计（README 对照表）

### Added

- 矩阵门禁第 13 行：双实例共享 DB/Redis 的并发计数器恢复（P1-1）——
  从 DB 权威值收敛、无陈旧命中（真实 MySQL + Redis，3 遍稳定）

### Fixed（外部评审第六轮）

- **P0 三项主张核实结果：均不成立**（当前 HEAD `562d42d` 编译/vet 通过，
  方法名已全量更名 Sync*，Redis 适配器已实现 SetIntMax Lua 脚本）——
  评审者看的是第五轮修复前的旧快照
- **§4 采纳**：`recoverCountersFromDB` 的"先删再写"两步竞态（删除与回填
  之间的并发同步可看到空键）——已删除 Delete 前置步骤，Lua 的
  `tonumber(cur)` 解析失败分支本身就是原子的损坏值替换；新增专项测试
  `TestSetIntMax_CorruptValue_AtomicSelfHeal`（损坏键上的并发写入收敛到
  最大真值）
- **§6 采纳**：README 残留"提交后才递增"旧措辞已更正为"同事务递增"；
  设计文档 §6 开头新增组件职责表（MySQL 权威 / Redis 单调副本 /
  SyncSubjectVersion / SyncEpoch / SetIntMax 六行）
- **§5 核实**：七操作同事务验证通过（grep 证据：base 10 处 +
  tenant 4 处 BumpCounterTx 全部在 `tx` 闭包内）

### Fixed（第六轮自审）

- **Simple 模式查询放大**：DB 权威协议落地后，NoopCache 的 GetInt 恒返回
  "缺失"（ok=false），导致 Simple 模式每次鉴权触发 2 次权威计数器恢复 +
  2 次写回复核兜底 = **+4 次 DB 查询**（8 次 vs 原有 4 次）。Simple 模式的
  性能契约是"仅原有聚合查询"——现 NoopCache 短路整个计数器协议直接回源，
  回归测试断言 Simple 模式零计数器查询

### Docs（外部审核第五轮第三、四条）

- **设计文档 §6 整体重写**（v0.3.0-design → v0.4.0-design）：旧版仍描述
  "事务提交后 Redis 递增 / INCR / SETNX 基线"协议，与数据库权威实现不符。
  新 §6：权威计数器同事务递增、Redis 忠实副本（SetIntMax 单调写唯一原语）、
  禁止模式表（INCR / 无条件 SET / SETNX 0 及各自造成的真实缺陷）、
  失效边界表（用户级 subject version / 角色级全域 epoch + 性能取舍声明）、
  故障语义与一致性边界按权威协议重述
- README 失效边界表明确化（含全域冷启动的取舍声明）
- 审计事务性 Outbox 方案定稿（docs/phase3-evaluation.md 新增第三节）：
  业务变更与 Outbox 事件同事务提交 + Worker 投递 + Event.ID 幂等消费；
  P1 优先级，不阻塞缓存一致性

### Fixed（外部审核第五轮 P0）

- **副本同步弃用 INCR，改用权威真值 + `SetIntMax` 单调写回（P0-1）**：
  旧实现的并发窗口——操作 A 的 INCR 失败并删副本后，操作 B 的
  INCR-from-missing 从 1 重建副本，与权威值产生持久偏差，且读者看到
  "在场且合法"的计数器不会触发恢复，可能命中旧生成键。新语义：提交后
  读 `rbac_counters` 真值，以 Lua 原子单调写同步（仅当前值缺失/损坏/
  更小时写入，永不回退）；任一步失败删副本回退 DB。
  `PermissionCache` 接口移除 `Incr`/`SetInt`，新增 `SetIntMax`（Breaking）
- **恢复路径同样使用 `SetIntMax`（P0-2）**：恢复与更新同步乱序并发时
  副本只会前进——适配器单测直接复现 [10,11,9,12,8] 乱序并发收敛到 12
  （真实 Lua 语义）；矩阵行 7/8 重写为偏差场景（副本删除后恢复=真值
  而非 1；恢复×再变更 epoch 单调前进）

### Fixed（第三轮自审）

- `IncrEpoch` 重建碰撞洞（第三轮审核发现）：epoch 键被淘汰后经**失效路径**
  （而非读路径）重建时，INCR-from-missing 得 1 与历史 epoch=1 时代的
  (1, vN) 生成键碰撞且读者信任在场计数器——修复为先 SETNX 探测、
  新建即全域清洗再递增（读路径的重建清洗无法覆盖此入口）；
  回归测试覆盖新建清洗与在场不清洗两分支

### Security（外部审核问题 1，P0）

- **Redis 计数器丢失/损坏不再导致旧权限复活**：三层修复——
  1. `GetInt` 值损坏改为返回错误（缓存状态不可信），不再静默当作 0
  2. 基线协议：计数器缺失（首写或被 allkeys-* 淘汰）→ 旁路缓存读写；
     flight 内 `InitCounter`（SETNX 0）重建基线，**若为新建（键曾丢失）
     先以 `DeleteByPattern` 清洗全域/该主体权限条目**，使重建值不可能
     命中历史生成键（重建到任何固定值都与历史碰撞——清洗后命名空间从零开始）
  3. 失效自愈：`IncrSubjectVersion` 递增后删除新生成键旧条目
- 已知残余窗口：SETNX 与清洗完成之间（毫秒级）的理论陈旧读；运维第一道
  防线为 `noeviction`/`volatile-*` 淘汰策略（计数器是唯一无 TTL 键族），README 已文档化
- 端到端回归：epoch 键淘汰 + 陈旧条目存活 → 必须读库真相（真实 Redis 验证）

### Added（外部审核问题 2/3/四/五）

- `ErrInvalidationFailedAfterCommit` / `ErrAuditFailedAfterCommit` 哨兵：
  数据库已提交、缓存失效/审计写入失败时明确标记；各管理操作幂等，
  **重试同一操作安全**（重试成功即补做失效）——半成功状态从"含糊报错"
  变为"可操作恢复"
- **缓存诊断**：`app.CacheDiagnostics(ctx, ac)`——运行模式（simple/cached）、
  epoch/版本计数器状态、当前生成键与权限条目存在性、失效递增尝试/失败计数；
  README 新增"运行模式"（Simple 默认 / Cached 可选）与排障指引
- **失效矩阵发布门禁**（12 行）：角色/权限/用户禁用、计数器淘汰与损坏、
  递增失败哨兵与重试、Redis 恢复收敛、临时授权到期、并发角色编辑一致性、
  租户隔离与超管边界——真实 MySQL + 真实 Redis，CI 与 release 均运行
- 模块依赖解析：`Module.Dependencies()` + 拓扑排序（存在性/循环/重名/nil
  检查），注册顺序不再需要人工保证
- 配置校验：`ErrInvalidOption`（nil 注册中心 / 负 TTL / 非法模块），配置错误
  转为明确错误而非运行时 panic
- 租户专项：管理面（List/SetPermissions/Grants）按域过滤的直传 ID 越域测试
- 安全文档：全部管理服务 godoc 增加 Security 注（不鉴权 operator）；
  种子入口标注"仅限可信初始化流程"

### Changed（Breaking，pre-1.0 收口）

- `cache.PermissionCache` 接口扩展：新增 `InitCounter`（返回是否新建）与
  `DeleteByPattern`——基线恢复协议所需。**自定义缓存实现需补齐这两个方法**
  （内置 NoopCache / Redis 适配器已实现）
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

### Fixed（CI 并发压力实测）

- `Grant`/`Revoke` 死锁重试：Revoke（单条 UPDATE，同样持唯一索引 next-key 锁）
  此前无重试，Grant 重试上限 3 次在双写者×25 轮相邻 subject 风暴下被穿——
  Revoke 补齐重试，上限统一提至 5 次（base/tenant 双实现）

### Fixed（复审补充）

- `App.Roles().List` 的公共可用性被 internal 迁移打断（参数
  `repository.RoleFilter` 不可外部命名）：新增 `rbac.RoleFilter` 类型别名恢复
- 死锁重试助手在 gormrepo 与 tenant 的重复实现合并为
  `internal/repository` 共享实现（"自包含"规则仅适用于 adapter/cache
  逃生舱包，tenant 本就依赖 internal）
- Makefile 中 sed 未转义点导致的路径二次改坏（`./interna./internal/...`）

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
