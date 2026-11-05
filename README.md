# go-rbac

面向 Go Web 后台项目的模块化 RBAC 权限基础设施库。

**基础权限能力开箱即用，高级功能按需启用，业务项目无需重复实现权限管理基础设施。**

- 经典 RBAC 模型：User → Role → Permission，多角色权限取并集，支持用户额外授权（含到期与撤销）
- 框架解耦：核心授权逻辑不绑定任何 Web 框架；提供 Gin 适配器（Fiber / Echo 按需扩展）
- 默认拒绝、失败关闭：无权限即拒绝；数据库 / 缓存 / 身份解析异常一律不得放行
- 版本化 SQL 迁移（`io/fs` embed + `schema_migrations`），幂等可重复执行
- **权限缓存（§6）**：版本号 + 全局 epoch 两级失效、写前复核、singleflight 击穿防护；
  不使用 Redis 也可正常运行（默认 NoopCache），Redis 适配器开箱即用
- 授权变更审计（Audit 模块）、角色模板（Template 模块）、菜单（Menu 模块）、
  数据权限（DataScope 模块）、多租户隔离（Tenant 模块）按需启用
- 适配器：Gin 与 net/http（标准库零依赖），核心不绑定任何框架
- 设计文档：[docs/go-rbac-design.md](docs/go-rbac-design.md)（v0.3.0-design 定稿）

## 快速开始（Gin）

```bash
docker compose up -d   # 可选：本地起一个 MySQL 8
go get github.com/animacaeli/go-rbac
```

```go
// 1. 声明业务权限（权限码格式：模块:操作，仅小写字母/数字/下划线/冒号）
permissions := registry.NewRegistry()
permissions.Register(
    registry.New("user:list", "用户列表", "用户管理"),
    registry.New("order:export", "导出订单", "订单管理"),
)

// 2. 组装（New 无副作用：不迁移、不触库）
app, err := rbac.New(
    rbac.WithDB(db),                          // 必需，DSN 建议 parseTime=true&loc=UTC
    rbac.WithPermissionRegistry(permissions), // 可选
    // rbac.WithSubjectStatusChecker(...),    // 可选：账号状态检查
)
// 3. 显式迁移 + 权限同步（幂等）
err = app.Migrate(ctx)
_, err = app.SyncPermissions(ctx)

// 4. 超管种子（唯一入口：管理接口不可授予超管角色）
err = app.SeedSuperAdmin(ctx, "10001")

// 5. 路由只声明权限码
guard := ginadapter.New(app.Authorizer(), mySubjectResolver)
api.GET("/users", guard.Require("user:list"), userController.List)
api.GET("/orders/export", guard.Require("order:export"), orderController.Export)

// 6. 启动期交叉校验：拼写错误直接启动失败，而非运行时永远 403
err = app.ValidatePermissionCodes(guard.DeclaredCodes()...)
```

业务项目只需要提供：用户认证、身份解析器（`core.SubjectResolver`）、权限声明、数据库。
完整可运行示例见 [examples/gin-basic](examples/gin-basic)。

```bash
export RBAC_DSN='root:rootpass@tcp(127.0.0.1:3306)/go_rbac?parseTime=true&loc=UTC&charset=utf8mb4'
export RBAC_SUPER_ADMIN=10001
go run ./examples/gin-basic

curl -H 'X-Subject-ID: 10001' localhost:8080/api/whoami          # 超管
curl -H 'X-Subject-ID: 20001' localhost:8080/api/users           # 角色授权 → 200
curl -H 'X-Subject-ID: 20001' localhost:8080/api/orders/export   # 未持有 → 403
curl localhost:8080/api/users                                    # 未认证 → 401
```

## 管理接口

```go
// 角色管理（内置角色受保护：不可删除/禁用/经管理接口授予）
app.Roles().Create(ctx, operator, "ops", "运营专员", "描述")
app.Roles().SetStatus(ctx, operator, roleID, model.RoleStatusDisabled)
app.Roles().SetPermissions(ctx, operator, roleID, []string{"user:list", "order:export"})
app.Roles().Delete(ctx, operator, roleID) // 正在被使用的角色拒绝删除

// 用户角色
app.UserRoles().Assign(ctx, operator, "10001", roleID)
app.UserRoles().Revoke(ctx, operator, "10001", roleID)

// 用户额外授权（临时授权）：完整生命周期，撤销/过期记录保留可审计
expiry := time.Now().Add(24 * time.Hour)
app.Grants().Grant(ctx, operator, "10001", "order:export", &expiry, "临时项目需要")
app.Grants().Revoke(ctx, operator, "10001", "order:export")
```

**授权者持权约束（默认开启，§2.2）**：授权者必须持有拟授予的权限，超级管理员除外。
该约束阻止权限越权扩散，可用 `rbac.WithGrantorConstraint(false)` 关闭。

**超级管理员（§7.3）**：内置受保护角色（`super_admin`，`is_builtin=1`），仅能通过
`SeedSuperAdmin` 种子初始化；`HasPermission` 对超管恒真，`GetPermissions` 返回空集合，
前端应以 `IsSuperAdministrator` 单独判断。

## 运行模式

| 模式 | 实现 | 默认 | 适用 |
|---|---|---|---|
| **Simple** | NoopCache，每次鉴权回源数据库 | **是** | 小型项目、默认接入：零缓存一致性面，行为最直观 |
| **Cached** | 注入 Redis 等缓存后自动进入 | 否 | 有性能要求的生产环境：版本号 + epoch 两级失效等完整机制 |

默认 `rbac.New(rbac.WithDB(db), ...)` 即 Simple；`rbac.WithCache(rediscache.New(cli))` 后自动切换为 Cached——两种模式语义等价（§6 一致性边界除外），可随时升级。

## 权限缓存（§6）

不注入缓存时默认 NoopCache（每次回源数据库，行为正确只是慢）。注入 Redis 后获得
完整的一致性机制：

```go
import rediscache "github.com/animacaeli/go-rbac/cache/redis"
import "github.com/redis/go-redis/v9"

cli := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
app, err := rbac.New(
    rbac.WithDB(db),
    rbac.WithCache(rediscache.New(cli)), // 可选：rbac.WithCacheTTL(10 * time.Minute)
)
```

### 版本号权威来源（数据库）

授权变更与权威版本号递增在**同一数据库事务**内提交（`rbac_counters` 表）。
Redis 中的 epoch / 主体版本只是该权威值的**缓存副本**：

- 副本丢失 / 损坏 / Redis 故障 → 读路径从数据库回填权威值（`SetInt`），
  生成键永远取真实版本——不存在"重置归零后与历史生成键碰撞"这一类问题
- 副本同步失败（INCR 失败）→ 删除该副本 → 后续读回退数据库权威值，
  正确性不受影响（仅该主体短暂失去缓存加速）
- 角色级变更（权限分配/禁用/删除、权限禁用、同步）递增 **epoch**（一次原子
  失效全域，消除逐用户 fan-out 的部分成功窗口）；用户级变更递增主体版本

已知边界：Redis 可读但不可写的窄窗口内（如只读副本），副本可能落后于
权威值直至 TTL；`ErrInvalidationFailedAfterCommit` 语义见下文重试分级。

机制要点（详见设计文档 §6）：

- **两级失效**：用户级版本号递增（授权变更精确失效）+ 全局 epoch 递增
  （权限禁用等低频全局事件，全员冷启动一次）；权限码字面进入生成键
  `perm:v{epoch<<32|version}`，旧数据只可能落在旧生成键下，新读者不可达
- **不变性（承重墙）**：版本号只在数据库事务提交成功后递增——版本号只允许
  落后于数据，永远不允许超前于数据
- **写前复核**：回填缓存前复核生成键未变，已变则丢弃结果重走流程
- **击穿防护**：singleflight 合并同主体并发回源
- **临时授权**：缓存 TTL 不超过最近一条授权到期时间，查询层始终校验 expires_at
- **故障语义**：Redis 故障时鉴权回源数据库；管理接口的版本递增失败整体报错
  （权限管理在 Redis 故障期间不可用——可用性换一致性的刻意选择）

一致性边界（§6.7）：正常运行下授权撤销在"事务提交 + 版本递增完成"后即时生效；
不提供跨缓存层的严格线性一致。

**Redis 淘汰策略要求（Cached 模式）**：版本号/epoch 计数器是库内唯一无 TTL 的
键族，必须不被淘汰——Redis 需配置 `noeviction` 或任意 `volatile-*` 策略
（只淘汰带 TTL 的权限条目）。若误用 `allkeys-*`：代码侧有基线恢复协议兜底
（计数器丢失→旁路缓存+重建时清洗全域条目，见 §6.2 实现），但重建窗口
（毫秒级）内存在理论上的陈旧读取，不应依赖。

**缓存诊断**：`app.CacheDiagnostics(ctx, ac)` 返回运行模式、epoch/版本计数器
状态、当前生成键与权限条目存在性、本进程失效递增尝试/失败计数——排障
"为什么权限没失效"的第一现场。命中率/耗时经 `core.CountingMetrics` 注入采集。

大小写语义：MySQL 排序规则（utf8mb4_0900_ai_ci）下 `subject_id` 不区分大小写，
缓存 key 区分——同一身份的不同拼写会得到一致的授权结果，但缓存条目各自独立
（仅冗余，无正确性影响）；权限码由注册中心校验拒绝大写，无此问题。业务侧
建议 subject_id 统一小写。

## 可选模块

```go
import (
    "github.com/animacaeli/go-rbac/modules/audit"
    "github.com/animacaeli/go-rbac/modules/template"
)

app, err := rbac.New(
    rbac.WithDB(db),
    rbac.WithPermissionRegistry(permissions),
    rbac.WithModules(
        audit.New(), // 授权变更审计（rbac_audit_logs，随 Migrate 自动建表）
        template.New( // 角色模板：Snapshot/Copy 模式
            template.Define("ops_lead", "运营主管", "用户与订单管理",
                "user:list", "order:list", "order:export"),
        ),
    ),
)
// 模板创建角色（复制当前模板权限快照，后续模板变化不影响已创建角色）：
role, err := tplModule.CreateFromTemplate(ctx, operator, "ops_lead", "ops_42", "运营主管-42")
// 审计查询（需 rbac:audit:read 权限保护）：
logs, err := audit.NewQuery(auditModule).List(ctx, audit.Filter{Operator: "10001"})
```

Audit 提供两档失败策略，注意二者**不是**同一保证：

| 策略 | 行为 | 保证 |
|---|---|---|
| Strict（默认） | 审计写入失败 → 操作返回 `ErrAuditFailedAfterCommit` | 投递失败可见、可告警；**不是**事务性审计（业务变更已提交，存在审计缺口窗口） |
| LogOnly | 失败仅记日志，操作继续 | 管理可用性优先，接受审计缺口 |

事务性审计（业务变更与审计事件同事务提交 + Outbox 可靠投递 + 事件 ID
幂等消费）是规划中的增强（`docs/phase3-evaluation.md`）。`Event.ID` 已就位，
消费端可据此去重。

### Menu（§2.7）/ DataScope（§2.8）

```go
menuM := menu.New()
ds := datascope.New()
app, _ := rbac.New(..., rbac.WithModules(audit.New(), menuM, ds))

// 声明菜单（幂等）：目录无权限关联=所有人可见；页面关联权限后需持有（OR 语义）
_ = menuM.Declare(ctx,
    menu.Item{Code: "biz", Name: "业务", Type: menu.TypeDirectory},
    menu.Item{Code: "biz_users", Parent: "biz", Name: "用户", Type: menu.TypePage,
        Path: "/users", Component: "UserList", Permissions: []string{"user:list"}},
)
tree, _ := menuM.ResolveVisibleMenus(ctx, ac) // 主体可见菜单树

// 数据范围：多角色取最宽；未配置默认 SELF（deny-by-default）；超管恒 ALL
_ = ds.SetRoleScope(ctx, operator, roleID, "order", datascope.ScopeDepartmentAndChildren)
scope, _ := ds.ResolveDataScope(ctx, ac, "order") // 业务自行应用到查询
```

前端隐藏菜单只是体验优化，后端必须独立鉴权（§2.7）。

### Multi-Tenant（§2.9）

```go
tenantMod := tenant.New()
app, _ := rbac.New(..., rbac.WithModules(tenantMod)) // 必须注册在首个
_ = app.Migrate(ctx)   // §5.5 迁移契约：加列 tenant_id → 回填 → 重建三唯一键（集成测试验收）

// 请求入口：从可信上下文解析租户（TenantResolver）并注入
ctx = core.ContextWithTenant(ctx, tenantID)

// 种子：平台超管（default 域，全租户生效）/ 租户超管（仅本域）
_ = app.SeedSuperAdmin(ctx, "platform-admin")
_ = tenantMod.SeedSuperAdminInTenant(ctx, "acme", "acme-admin")
```

启用后语义：`AuthorizationContext.TenantID` 必须提供（缺失即 fail closed）；
三张租户归属表（roles / user_roles / user_grants）读写按租户隔离；
跨租户角色引用被结构性拒绝；缓存 key 按授权域隔离；
平台超管以任意租户上下文恒真，租户超管仅本域。

## 错误语义（§2.6）

| 情况 | HTTP 状态 |
|---|---|
| 未认证（身份解析失败） | 401 |
| 已认证但无权限 / 账号非活跃 | 403 |
| 鉴权服务异常（fail closed） | 503（默认，可定制） |
| 正常授权 | 继续执行 |

401 / 403 / 503 响应体可通过 `ginadapter.WithUnauthorizedHandler` 等注入定制。

## 数据库

- MySQL 8.0+ / InnoDB / `utf8mb4_0900_ai_ci`；`DATETIME(3)` + 应用层 UTC
- 五张核心表：`rbac_roles` / `rbac_permissions` / `rbac_user_roles` /
  `rbac_role_permissions` / `rbac_user_grants`（v1 冻结稿，见设计文档 §5.2）
- 表前缀固定 `rbac_`；v1 无 tenant_id（多租户为 Phase 3 可选模块，核心已预留授权域）
- `app.Migrate(ctx)` 执行 Core → 扩展模块注册顺序的版本化迁移；生产环境建议在发布流程统一执行

### 操作重试语义分级

收到 `ErrInvalidationFailedAfterCommit` 后重试同一操作的正确性因操作而异：

| 操作 | 重试语义 |
|---|---|
| SetPermissions / SetStatus / Assign / AssignBatch | **幂等**：重试安全，结果一致 |
| Grant | 非幂等但安全：撤销旧行+插入新行——重试增加历史记录与审计事件条数，授权结果一致 |
| Revoke（额外授权撤销） | 首次可能已成功（错误仅来自失效同步）→ 重试返回 `ErrGrantNotFound` 即表示此前已生效 |

权威版本随变更事务递增，任何情况下重试不影响缓存正确性。

## 管理接口安全责任边界

`app.Roles() / UserRoles() / Grants() / Permissions()` 的服务方法**不鉴权
operator**——不检查调用者是否持有 `rbac:*` 管理权限（服务只执行业务规则：
授权者持权约束、内置保护等）。所有调用方（HTTP 接口、内部 Job、CLI）必须
先自行完成调用者授权，例如：

```go
api.POST("/admin/roles", guard.Require("rbac:role:create"), roleHandler.Create)
```

`SeedSuperAdmin` / `tenant.SeedSuperAdminInTenant` 同样不鉴权，只能用于可信
初始化流程（部署脚本/初始化 Job），绝不可暴露给业务请求。

**发布门禁**：`cache/redis` 的失效矩阵套件（12 行场景：角色/权限/用户禁用、
计数器淘汰与损坏、递增失败与恢复、临时授权到期、并发编辑、租户隔离、
超管边界）在真实 MySQL + 真实 Redis 上运行，CI 与 release 流水线均以此为门禁。

## 路线图

- [x] **Phase 1 核心 RBAC**：模型 / 迁移 / Registry + 同步 / 角色与授权管理服务 /
      授权服务（含超管）/ Gin 中间件 / 启动期校验 / 内置 `rbac:*` 权限码 / NoopCache
- [x] **Phase 2 缓存与管理能力**：Redis Adapter、版本号 + epoch 两级失效（写前复核、
      singleflight）、失效矩阵全覆盖测试、临时授权过期、角色模板、权限批量操作、
      Audit 模块（事件总线 + Strict/LogOnly 策略）、CountingMetrics、§9.4 性能基线
      （命中路径 P99 < 1ms、冷聚合 P99 < 50ms、1k 用户批量失效 < 100ms、
      500 权限幂等同步 < 2s，实测见 CI / `make bench`）
- [x] **Phase 3 高级模块**：Menu（OR 语义 + 可见树解析）、DataScope（四枚举取最宽、
      默认 SELF）、Multi-Tenant（§5.5 迁移契约测试 = 第一验收项：升级/全新双路径 +
      双租户隔离/跨租户拒绝/平台与租户超管边界/缓存域隔离）、net/http 适配器、
      CUSTOM 数据范围与 Outbox 评估（结论见 [docs/phase3-evaluation.md](docs/phase3-evaluation.md)，
      均维持延后并有明确触发条件）
- [x] **Phase 4 稳定性与生态**：godoc 文档与示例、接入示例（basic / redis /
      tenant）、MySQL 8.0 + 8.4 LTS 兼容矩阵（[5.7 评估：不支持]
      (docs/db-compatibility.md)）、并发授权与主从延迟边界测试、§9.3 安全
      套件（含 Redis 故障矩阵）、pkg.go.dev 定名查重（保留 go-rbac）、
      CHANGELOG 与 tag 触发的发布流水线

### 发布流程

版本记录在 [CHANGELOG.md](CHANGELOG.md)（Keep a Changelog 格式）。
发布 = 在 CHANGELOG 落定版本区段后打 tag：

```bash
git tag v0.x.0 && git push origin v0.x.0   # 触发 .github/workflows/release.yml：
                                            # 全量测试 → 从 CHANGELOG 提取区段 → GitHub Release
```

## 开发

常用命令见 `make help`：

```bash
make check             # 本地提交前检查（与 CI 一致：gofmt / vet / golangci-lint / 单元测试）
make cover-integration # 单元 + 集成合并覆盖率（库代码口径）
make test-integration  # 集成测试（自动用 docker compose 拉起 MySQL 8，无需手动设 DSN）
make vuln              # govulncheck 漏洞检测
make cover             # 单元测试 + 覆盖率汇总
make mocks             # 重新生成测试替身（mockery v3 → test/mocks）
make hooks             # 安装 git hooks（首次 clone 后执行一次）
```

Git hooks（`make hooks` 安装）：

- **pre-commit**（秒级拦截）：暂存内容涉及 Go 代码时执行 gofmt 检查、
  `go mod tidy` 幂等检查、`go vet`
- **pre-push**（分钟级完整检查）：build / vet / golangci-lint / govulncheck /
  `go test -race`；未安装的工具自动跳过（CI 中强制执行）

CI（`.github/workflows/ci.yml`）：lint（golangci-lint）、单元测试矩阵
（最低支持版 + stable，含竞态检测与覆盖率）、集成测试矩阵（MySQL 8.0 +
8.4 LTS × Redis 7）、govulncheck 漏洞检测，push / PR 自动触发。

> 注：设计文档 §4.7 的内置权限码 `rbac:user:assign-role` 含连字符，与 §2.2/§2.3
> 冻结的权限码字符集（小写字母/数字/下划线/冒号）冲突，实现规范化为
> `rbac:user:assign_role`。

## License

[MIT](LICENSE)
