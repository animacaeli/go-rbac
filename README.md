# go-rbac

面向 Go Web 后台项目的模块化 RBAC 权限基础设施库。

**基础权限能力开箱即用，高级功能按需启用，业务项目无需重复实现权限管理基础设施。**

- 经典 RBAC 模型：User → Role → Permission，多角色权限取并集，支持用户额外授权（含到期与撤销）
- 框架解耦：核心授权逻辑不绑定任何 Web 框架；提供 Gin 适配器（Fiber / Echo 按需扩展）
- 默认拒绝、失败关闭：无权限即拒绝；数据库 / 缓存 / 身份解析异常一律不得放行
- 版本化 SQL 迁移（`io/fs` embed + `schema_migrations`），幂等可重复执行
- 不使用 Redis 也可正常运行（默认 NoopCache；Redis 版本号缓存于 Phase 2 提供）
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

## 路线图

- [x] **Phase 1 核心 RBAC**：模型 / 迁移 / Registry + 同步 / 角色与授权管理服务 /
      授权服务（含超管）/ Gin 中间件 / 启动期校验 / 内置 `rbac:*` 权限码 / NoopCache
- [ ] Phase 2 缓存与管理：Redis Adapter、版本号 + epoch 两级失效、singleflight、
      角色模板、Audit 模块、Metrics 落地
- [ ] Phase 3 高级模块：Menu / DataScope / Multi-Tenant（第一验收项 = §5.5 迁移契约测试）
- [ ] Phase 4 稳定性与生态：文档、兼容性测试、CI、发布规范

## 开发

常用命令见 `make help`：

```bash
make check             # 本地提交前检查（与 CI 一致：gofmt / vet / golangci-lint / 单元测试）
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
（最低支持版 + stable，含竞态检测与覆盖率）、MySQL 8 集成测试、govulncheck
漏洞检测，push / PR 自动触发。

> 注：设计文档 §4.7 的内置权限码 `rbac:user:assign-role` 含连字符，与 §2.2/§2.3
> 冻结的权限码字符集（小写字母/数字/下划线/冒号）冲突，实现规范化为
> `rbac:user:assign_role`。

## License

[MIT](LICENSE)
