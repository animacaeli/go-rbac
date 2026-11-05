# Go-RBAC 产品与技术设计文档

**项目名称：** go-rbac（暂定，发布前需在 pkg.go.dev 查重）
**文档类型：** 产品需求与技术架构设计
**当前版本：** v0.4.0-design
**技术语言：** Go
**目标框架：** Gin 优先，支持后续扩展 Fiber、Echo、net/http
**核心技术：** GORM、MySQL、Redis（可选）

---

## 修订记录

| 版本 | 日期 | 说明 |
|---|---|---|
| v0.1.0-design | 2026-11 | 初稿 |
| v0.2.0-design | 2026-11-04 | 设计评审修订稿：冻结缓存一致性方案与数据库 Schema；新增 Module Registry、中间件错误响应定制、账号状态检查接口、观测接口、启动期权限码校验、内置管理权限码；明确多租户策略与租户迁移契约；部分新增项标记待确认 |
| v0.4.0-design | 2026-11-05 | §6 整体重写（随实现定稿）：版本号权威来源迁移至数据库（rbac_counters 同事务递增），Redis 降级为忠实副本（SetIntMax 单调写为唯一计数器写原语）；失效矩阵角色级全部改 epoch（消除逐用户 fan-out 部分成功）；故障语义与一致性边界按权威协议重述。技术实现细节见 CHANGELOG Unreleased 与 README |
| v0.3.0-design | 2026-11-04 | 定稿：全部待确认项落实——①通配符权限 v1 不支持，按字面匹配；②"授权者必须持有拟授予权限"默认开启；③Authorizer 签名采用 AuthorizationContext；④数据权限四种枚举范围取最宽合并，CUSTOM 延后；⑤表前缀 v1 固定 `rbac_`，可配置推迟；⑥Casbin Adapter 移出路线图；⑦Repository 接口 v1 保持内部。移除全部评审标记 |

---

# 一、项目概述

## 1.1 项目背景

在多个 Go 后台管理系统的开发过程中，通常都需要重复实现 RBAC（Role-Based Access Control）权限管理体系。

常见的重复开发内容包括：

- 用户与角色的关联管理。
- 角色与权限的关联管理。
- 权限资源定义和注册。
- 用户额外授权。
- API 接口鉴权。
- Gin 权限中间件。
- 权限数据缓存。
- 菜单与权限关联。
- 数据权限控制。
- 权限管理相关数据库表结构。

这些功能具有较高的通用性，但不同项目往往会重复实现，导致开发成本增加、设计不统一、后续维护困难。

虽然 Casbin 等授权框架能够提供通用的策略判断能力，但它们更偏向于授权引擎，并不直接提供一套完整的后台 RBAC 业务体系。

因此，希望开发一个面向 Go 后台项目的通用 RBAC 公共库，将常用权限管理能力标准化、组件化，使新项目能够快速接入。

## 1.2 产品定位

go-rbac 是一个面向 Go Web 后台项目的模块化 RBAC 权限基础设施库。

核心定位：

**基础权限能力开箱即用，高级功能按需启用，业务项目无需重复实现权限管理基础设施。**

产品遵循以下原则：

1. 开箱即用：基础功能提供完整的数据模型、数据库迁移、权限服务和鉴权中间件。
2. 框架解耦：核心权限逻辑不绑定 Gin、Fiber 等 Web 框架。
3. 模块化：多租户、数据权限、菜单、审计等高级功能按需启用。
4. 业务解耦：不接管业务项目的用户认证、JWT 和业务逻辑。
5. 安全优先：默认拒绝未授权请求，鉴权异常时失败关闭。
6. 可扩展：允许业务项目注入身份解析器、存储适配器和扩展模块。
7. 轻量化：不为了理论上的完整性引入不必要的复杂度。

## 1.3 目标用户

- 使用 Go 开发后台管理系统的开发者。
- 使用 Gin、Fiber、Echo 等框架的 Go 后端项目。
- 需要快速构建权限管理体系的中小型团队。
- 需要在多个外包项目中复用统一权限模块的开发者。

## 1.4 非目标

go-rbac 第一阶段不负责：

- 用户注册、登录、密码管理。
- JWT、OAuth2、Session 等身份认证。
- 前端 Vue、React 等权限管理界面。
- 具体业务逻辑和业务状态校验。
- 业务数据模型定义。
- 完整 IAM / SSO 身份管理平台。
- 通用 ABAC 策略引擎。
- 企业组织架构和人事管理系统。
- 通配符权限（`*`、`user:*`）：v1 不支持，权限判断按权限码字面匹配。

---

# 二、产品功能设计

## 2.1 功能模块划分

整体分为基础模块和可选模块。

### 基础模块 Core

默认提供，无需额外安装高级模块。

| 模块 | 功能 | 优先级 |
|---|---|---|
| Permission | 权限资源管理 | P0 |
| Registry | 权限资源注册中心 | P0 |
| Role | 角色管理 | P0 |
| UserRole | 用户角色关联 | P0 |
| RolePermission | 角色权限关联 | P0 |
| UserGrant | 用户额外授权 | P0 |
| Authorization | 权限判断服务 | P0 |
| Middleware | HTTP 鉴权中间件 | P0 |
| Repository | 数据访问抽象 | P0 |
| Migration | 数据库迁移 | P0 |
| Cache Interface | 权限缓存抽象 | P0 |
| Module Registry | 扩展模块注册机制 | P0 |

### 可选模块 Extensions

根据业务项目需求启用。

| 模块 | 功能 | 优先级 |
|---|---|---|
| Redis Cache | Redis 权限缓存实现 | P0 |
| Role Template | 角色模板 | P1 |
| Menu | 菜单资源管理 | P1 |
| Data Scope | 数据权限 | P1 |
| Multi-Tenant | 多租户隔离 | P1 |
| Audit | 权限变更审计 | P1 |

说明：

- Casbin Adapter 经评审**不纳入路线图**：与产品定位存在张力（本库定位为业务级 RBAC 体系，Casbin 为通用策略引擎，二者重叠的部分本库已覆盖）。如未来出现明确需求再评估。
- Redis 虽然是可选依赖，但缓存抽象属于基础模块。没有 Redis 时，系统仍然必须能够正常运行。

## 2.2 RBAC 基础模型

采用经典 RBAC 模型：

User → Role → Permission

数据关系：

- 一个用户可以拥有多个角色。
- 一个角色可以分配给多个用户。
- 一个角色可以拥有多个权限。
- 一个权限可以分配给多个角色。
- 一个用户可以额外获得指定权限。

用户最终功能权限：

P(u) = 所有有效角色权限的并集 + 用户额外授权。

即：

P(u) = (∪ P(r)) ∪ E(u)

其中：

- P(u)：用户最终权限集合。
- P(r)：角色拥有的权限集合。
- E(u)：用户有效的额外授权集合。

### 默认授权策略

采用 Deny by Default：

- 没有权限即拒绝。
- 不支持显式 Deny。
- 多角色权限取并集。
- 用户额外授权只增加权限，不覆盖角色权限。
- 额外授权只能引用系统已经注册的权限资源。
- 用户额外授权不改变数据权限范围。
- 超级管理员采用受保护的特殊授权策略，不应成为普通管理员可随意授予的权限。

### 权限匹配语义

- v1 权限判断按权限码**字面匹配**，不支持通配符。
- `*`、`user:*` 不是合法权限码，Registry 注册时校验并拒绝。
- 权限码格式：`模块:操作`，小写字母、数字、下划线、冒号，注册时校验。

### 授权者约束

- 默认规则：**授权者必须持有拟授予的权限**，超级管理员除外。
- 该规则从机制上阻止普通管理员的权限越权扩散（不能授予自己没有的权限，也就无法通过授予他人再回收给自己形成闭环提权）。
- 规则可通过配置关闭，用于"权限管理员不需要持有全部业务权限"的场景。

## 2.3 权限资源注册中心 Permission Registry

权限资源由业务开发人员在代码中声明。

示例：

```go
permissions.Register(
    permissions.New("user:list", "用户列表", "用户管理"),
    permissions.New("user:create", "创建用户", "用户管理"),
    permissions.New("user:update", "修改用户", "用户管理"),
    permissions.New("user:delete", "删除用户", "用户管理"),

    permissions.New("order:list", "订单列表", "订单管理"),
    permissions.New("order:create", "创建订单", "订单管理"),
    permissions.New("order:export", "导出订单", "订单管理"),
)
```

应用启动时将权限注册信息同步至数据库。

同步规则：

1. 新增权限自动注册。
2. 新增权限不会自动授权给任何角色。
3. 修改权限名称、描述等展示元数据可以自动同步。
4. 权限 Code 必须稳定，不应随意修改。
5. 已删除的权限不立即物理删除，建议标记为禁用或废弃。
6. 数据库中存在但代码未注册的权限，应提供检查和清理机制。
7. 权限注册必须支持重复执行，确保幂等。
8. 注册时校验权限码格式（`模块:操作`），拒绝通配符与非法字符。

推荐权限编码格式：

`模块:操作`

例如：

- user:list
- user:create
- user:update
- user:delete
- order:export

权限 Code 是系统内部稳定标识，不应直接使用 URL 或 Controller 方法名称作为权限标识。

## 2.4 角色管理 Role

角色代表一组业务职责。

示例：

- 系统管理员
- 运营主管
- 运营专员
- 财务专员
- 普通员工

基础功能：

- 创建角色。
- 修改角色。
- 删除角色。
- 启用和禁用角色。
- 分配角色权限。
- 查询角色关联用户。
- 批量分配权限。
- 检查角色是否正在被使用。

角色删除应检查关联关系，避免误删正在使用的角色。

角色 Code 在同一授权作用域内唯一。内置受保护角色（如超级管理员载体，见 §7.3）通过 `is_builtin` 标记，禁止通过管理接口删除或禁用。

### 角色模板 Role Template

角色模板是开发人员预设的常用角色配置。

例如：

| 模板 | 权限示例 |
|---|---|
| 系统管理员 | 全部业务权限 |
| 运营主管 | 用户、订单管理和导出 |
| 运营专员 | 用户和订单基础操作 |
| 财务专员 | 财务、订单查看和导出 |
| 普通员工 | 基础查询权限 |

模板采用 Snapshot / Copy 模式：

- 创建角色时复制模板权限。
- 后续模板变化不自动影响已创建角色。
- 初期不实现自动同步。
- 后续可以提供人工同步模板更新的功能。

模块级快捷授权，例如全选、只读、全部操作，仅作为权限管理界面的批量勾选能力，不作为新的授权资源。

## 2.5 用户额外授权 User Grant

支持在角色权限之外，单独向用户授予指定权限。

典型场景：

某用户拥有运营专员角色，但因为临时工作需要，需要额外获得订单导出权限。

管理员可以直接授予：

`order:export`

不需要修改整个角色的权限，也不需要创建一个只差一个权限的新角色。

记录字段：

| 字段 | 说明 |
|---|---|
| subject_id | 外部用户标识 |
| permission_id | 权限资源 ID |
| expires_at | 授权到期时间，可空（NULL=永久） |
| reason | 授权原因 |
| created_by | 授权操作人 subject_id |
| created_at | 授权时间 |
| revoked_at | 撤销时间，可空 |
| revoked_by | 撤销操作人 subject_id |

生命周期规则：

- 过期或撤销的授权记录**保留不删除**，便于审计。
- 同一 (subject_id, permission_id) 至多一条**未撤销**的授权记录：
  - 主防线：服务层事务内，先撤销冲突的未撤销行（含已过期未撤销），再插入新授权。
  - 兜底：数据库生成列 + 唯一约束拦截并发漏网（见 §5.2）。
- 重新授权 = 撤销旧活跃行 + 插入新行，而非更新复用。

用户额外授权不能绕过：

- 用户账号禁用。
- 租户隔离。
- 数据权限。
- 业务状态规则。

## 2.6 API 鉴权 Middleware

提供统一的 Web 框架适配器。适配器在构造时注入 Authorizer 与身份解析器，路由处只声明权限码（全文档统一此签名）：

```go
guard := ginadapter.New(auth, resolver)

api.GET(
    "/users",
    guard.Require("user:list"),
    userController.List,
)

api.POST(
    "/users",
    guard.Require("user:create"),
    userController.Create,
)

api.DELETE(
    "/users/:id",
    guard.Require("user:delete"),
    userController.Delete,
)
```

鉴权顺序：

1. 业务项目完成用户身份认证。
2. 身份解析器获取 subject_id。
3. （若注入）账号状态检查器校验 subject 活跃状态。
4. RBAC 中间件获取路由要求的权限。
5. Authorization Service 执行授权判断。
6. 授权成功进入 Controller。
7. 授权失败返回 HTTP 403。
8. 授权服务异常时拒绝访问，不能放行。

错误语义：

| 情况 | HTTP 状态 |
|---|---|
| 未认证（身份解析失败） | 401 |
| 已认证但无权限 / 账号非活跃 | 403 |
| 鉴权服务异常 | 500 或统一服务不可用错误 |
| 正常授权 | 继续执行 |

核心 RBAC 不负责认证。身份解析失败时不得将请求视为匿名授权通过。

### 错误响应定制

401 / 403 / 500 的响应体格式因项目而异，适配器必须支持注入自定义响应处理器：

```go
guard := ginadapter.New(
    auth,
    resolver,
    ginadapter.WithUnauthorizedHandler(func(c *gin.Context, err error) {
        c.JSON(401, gin.H{"code": 401, "msg": "unauthenticated"})
    }),
    ginadapter.WithForbiddenHandler(func(c *gin.Context) {
        c.JSON(403, gin.H{"code": 403, "msg": "forbidden"})
    }),
    ginadapter.WithUnavailableHandler(func(c *gin.Context, err error) {
        c.JSON(503, gin.H{"code": 503, "msg": "authorization unavailable"})
    }),
)
```

未注入时使用库内置的默认 JSON 响应。

### 启动期权限码校验

路由声明的权限码如果在 Registry 中不存在（拼写错误、漏注册），运行时表现为永远 403 且难以定位。因此提供启动期交叉校验：

- 应用启动时，将所有路由（或集中声明的权限码清单）与 Registry 交叉比对。
- 发现未注册的权限码直接启动失败（fail fast），将拼写错误消灭在部署前。

## 2.7 菜单模块 Menu

菜单是前端导航资源，不等同于权限资源。

两者采用可选关联模式：

- Menu 可以关联 Permission。
- Menu 也可以不关联 Permission。
- Permission 可以没有对应 Menu。
- Menu 负责导航展示。
- Permission 负责业务操作授权。
- API 负责后端接口保护。

菜单类型可以包括：

- 目录。
- 页面。
- 外部链接。

页面路由和组件配置作为菜单元数据管理，不必单独建立页面权限表。

菜单与权限支持可选关联，初期采用 OR 语义即可，复杂场景再扩展 AND 语义。

前端隐藏菜单或按钮只是用户体验优化，后端必须独立完成鉴权。

## 2.8 数据权限 Data Scope

数据权限与功能权限分离。

功能权限回答：

用户能否执行某个操作？

数据权限回答：

用户能操作哪些数据？

第一版数据权限范围（枚举型）：

| 类型 | 说明 |
|---|---|
| SELF | 仅本人数据 |
| DEPARTMENT | 本部门数据 |
| DEPARTMENT_AND_CHILDREN | 本部门及下级部门 |
| ALL | 全部数据 |

**合并语义：**

- 多角色数据范围合并 = **取最宽**。
- 说明：对枚举型范围，并集语义在数学上等价于"取最宽"，二者不矛盾；真正需要复杂集合运算的只有自定义范围。
- CUSTOM（自定义范围）**延后**至数据权限模块独立设计：它需要自定义集合（如部门集合）的存储模型与真正的并集运算，不宜在语义未定义清楚前进入 v1。

数据权限应独立于 Permission，不应该产生大量类似 `order:list:self` 的权限码。

模块提供数据范围解析能力，业务项目负责将解析结果应用到具体查询。

例如：

```go
scope, err := auth.ResolveDataScope(
    ctx,
    ac,
    "order",
)
```

之后业务项目将范围应用到 GORM 查询。

业务项目负责提供组织关系和业务数据字段映射。

数据权限的存储模型（如 `rbac_role_data_scopes`）由 datascope 模块迁移贡献，不在五张核心表内（见 §5.6）。

## 2.9 多租户 Multi-Tenant

多租户作为可选模块。当前策略：

### v1 决策

- v1 基础表**不含 tenant_id**。
- Core 从 v1 起预留**授权域（Scope）**概念：`AuthorizationContext` 携带 TenantID（见 §4.2），缓存 key 含 scope 槽位（见 §6.1）。
- 永不启用多租户的项目永远不付租户成本。
- TenantID 语义必须非歧义：
  - 单租户模式：TenantID 恒为空串，映射到 `default` 授权域。
  - 多租户启用后：TenantID 缺失 = fail closed，不得回退到 default 域。

### tenant 模块启用后需要承担

- 租户上下文解析。
- 租户角色与角色归属。
- 用户与租户关系。
- 用户权限缓存隔离（scope 生效）。
- 数据库查询隔离。
- 跨租户授权保护。
- 平台级管理员与租户级管理员的边界。

**迁移契约（tenant 模块的第一验收项）：**

tenant 模块的迁移必须完成：`ADD COLUMN tenant_id`（默认空串 = default 域）→ 存量数据回填 → 重建全部受影响唯一键：

- `rbac_roles.uk_code` → `(tenant_id, code)`
- `rbac_user_roles.uk_subject_role` → `(tenant_id, subject_id, role_id)`
- `rbac_user_grants` 唯一键 → `(tenant_id, subject_id, permission_id, active_flag)`

租户级管理员不能跨租户管理角色、用户和权限。

用户能否属于多个租户、平台角色如何表达，在多租户模块设计阶段确定；v1 只承诺上述预留点形状稳定。

## 2.10 审计模块 Audit

记录权限体系的重要变更：

- 角色创建、修改、删除。
- 角色权限变更。
- 用户角色变更。
- 用户额外授权。
- 用户授权撤销。
- 角色模板变更。
- 管理员身份及租户上下文。

审计记录应包含操作人、目标对象、变更内容、原因和时间。

审计模块不应影响基础授权判断的可用性，但涉及高风险操作时，应明确审计失败的处理策略。

审计模块是关联关系历史的唯一归属（见 §5.3）：`rbac_user_roles`、`rbac_role_permissions` 物理删除后，历史由审计记录追溯。

---

# 三、技术架构设计

## 3.1 整体架构

采用分层、模块化设计。请求处理链与分层依赖是两个视角，分开表达：

**请求处理链（运行时）：**

```text
Client
  → Web 框架（Gin / Fiber / Echo）
  → RBAC Adapter 中间件
      → SubjectResolver（业务实现）：解析 subject_id
      → SubjectStatusChecker（业务实现，可选）：校验账号状态
      → Authorizer（Core）：授权判断
          → Cache（version / epoch）
          → Repository（miss 回源，读主库）
  → Controller（授权通过）
```

**分层依赖（编译期，箭头为依赖方向）：**

```text
Business Application
 ├── Authentication（业务自理）→ SubjectResolver 实现
 └── Controllers
       ↓
 Framework Adapter（adapter/gin、adapter/fiber、adapter/echo）
       ↓ 仅依赖 Core 接口
 Core Authorization ←── Module Extensions（tenant / datascope / menu / template / audit）
       ↓
 Repository（gorm 实现）      Cache Interface（noop / redis 实现）
```

核心原则：

- Core 不依赖 Gin、Fiber 等框架。
- Core 不直接依赖 Redis。
- Core 不处理 JWT。
- 框架适配器负责 HTTP 层交互。
- Repository 负责持久化。
- 高级模块通过 Module Registry 接入，不反向污染 Core。

## 3.2 技术选型

| 技术 | 用途 | 是否强制 |
|---|---|---|
| Go | 核心开发语言 | 是 |
| GORM | ORM 与数据访问 | 第一版默认实现 |
| MySQL 8.0+ | 默认数据库 | 第一版主要支持 |
| Redis | 权限缓存 | 否 |
| Gin | Web 框架适配 | 否 |
| Fiber | Web 框架适配 | 否 |
| Echo | Web 框架适配 | 否 |

第一版以 GORM + MySQL 8.0+ + Gin 为主要落地组合，但核心权限服务不能依赖 Gin。

## 3.3 项目组织：单仓库、单 Go Module、多 Package（已定案）

第一版不拆多个 Go Module，不拆仓库。理由：主要目标是跨项目自用复用，而非建设第三方开发者生态。

```text
go-rbac/
├── go.mod
├── go.sum
├── README.md
├── LICENSE
│
├── rbac.go                 // New / Options
├── app.go                  // App：模块注册、迁移、服务获取
├── config.go
├── errors.go
│
├── core/                   // 授权、聚合、上下文
├── registry/               // 权限注册中心 + 同步
├── model/                  // 基础数据模型（GORM）
├── repository/             // 数据访问
│   ├── interfaces.go
│   └── gorm/
├── middleware/             // 与框架无关的中间件骨架、subject 工具
├── adapter/                // 框架适配器
│   ├── gin/
│   ├── fiber/              // 后续
│   ├── echo/               // 后续
│   └── http/
├── cache/
│   ├── interface.go
│   ├── noop.go
│   └── redis/
├── modules/                // 可选模块
│   ├── template/
│   ├── menu/
│   ├── datascope/
│   ├── tenant/
│   └── audit/
├── migrations/             // 版本化 SQL（io/fs embed）
└── examples/
    ├── gin-basic/
    └── gin-redis/
```

### Package 可插拔与依赖代价

- Go 按需导入保证：不 import 的 Package 不参与编译、不进入二进制。
- 但单 Module 下，fiber / echo / redis 等依赖仍会作为**间接依赖**进入业务项目的 go.mod / go.sum。这是已接受的代价。
- 逃生舱规则：**每个 adapter / cache 实现包必须完全自包含**（不共享库内胶水代码），未来若真撞上依赖冲突，将其抽成子 Module 是机械操作。

### Module Registry

采用显式注册，而不是在核心代码中到处判断功能是否开启：

```go
type Module interface {
    Name() string
    Register(app *App) error
    Migrations() []Migration
}
```

```go
app, err := rbac.New(
    rbac.WithDB(db),
    rbac.WithModules(
        tenant.New(),
        datascope.New(),
        audit.New(),
    ),
)
```

模块注册时可完成：

- 注册自己的 Service / Repository。
- 注册自己的数据库模型与迁移任务。
- 注册需要的扩展点。
- 检查模块依赖。

约束：

- `Register` 只做注册与收集，**不做数据库操作**，保证 `New()` 无副作用。
- 模块之间不直接互相依赖：DataScope 需要租户信息时，通过 Core 定义的 AuthorizationContext 获取，不 import tenant 模块。
- Module Registry 只是"模块注册 + 依赖检查 + 迁移收集"，**不做依赖注入容器**。

### 模块依赖关系

| 模块 | 依赖 |
|---|---|
| Core | 无高级模块依赖 |
| Redis Cache | Core Cache Interface |
| Gin Adapter | Core Authorizer / SubjectResolver 接口 |
| Fiber / Echo Adapter | 同上 |
| Role Template | Core Role、Permission |
| Menu | Core Permission |
| DataScope | Core Subject、AuthorizationContext |
| Multi-Tenant | Core Scope 扩展点 |
| Audit | Core 事件接口 |

### 数据库迁移采用模块贡献机制

每个模块只声明自己的 Migration，由统一迁移管理器按"Core → 模块注册顺序"执行：

```text
Core Migrations → Tenant Migrations（若启用）→ DataScope（若启用）→ Audit（若启用）
```

- Redis Cache 无数据库迁移。
- `app.Migrate(ctx)` 只是执行器；生产环境建议提供独立迁移命令或入口，而不是每次应用启动自动修改数据库。

## 3.4 目录边界说明

1. 第一版不需要把每个模块拆成独立仓库。
2. Repository 接口 v1 保持内部（GORM 实现内置），公开面只保留 Authorizer / PermissionCache / SubjectResolver / Module 等业务真正需要实现的接口——公开 Repository 等于承诺支持可替换存储，v1 不背此兼容性包袱；若未来出现第二存储需求再抽取为公开接口。
3. Fiber、Echo 等适配器按实际需求逐步实现。
4. `modules` 下的功能不能反向污染核心 RBAC 逻辑。

---

# 四、核心接口设计

## 4.1 RBAC 初始化

统一使用 Builder / Options 风格：

```go
app, err := rbac.New(
    rbac.WithDB(db),
    rbac.WithCache(cacheStore),              // 可选，默认 NoopCache
    rbac.WithPermissionRegistry(registry),
    rbac.WithSubjectStatusChecker(checker),  // 可选
    rbac.WithLogger(logger),                 // 可选
    rbac.WithMetrics(metrics),               // 可选
    rbac.WithModules(audit.New()),           // 可选
)

if err != nil {
    panic(err)
}

if err := app.Migrate(ctx); err != nil {      // 显式调用，New 不做
    panic(err)
}

if err := app.SyncPermissions(ctx); err != nil {
    panic(err)
}
```

规则：

- `New()` 只做组装与依赖检查，**不执行迁移、不触库**。
- 数据库连接、缓存实现、权限注册器、高级模块、日志、观测、账号状态检查器均为注入项。
- 迁移与权限同步由业务项目显式触发。

## 4.2 用户身份与授权上下文

RBAC 不管理业务用户表。用户 ID 采用外部身份标识，数据库使用 `VARCHAR(128)` 保存：

```go
type SubjectID string
```

例如：

```go
"10001"
"admin_10001"
"550e8400-e29b-41d4-a716-446655440000"
```

授权上下文（授权域显式化，Authorizer 全部方法接受 `AuthorizationContext` 而非裸 SubjectID）：

```go
type AuthorizationContext struct {
    SubjectID SubjectID
    TenantID  string // 单租户模式恒为空串（default 域）；
                     // 多租户启用后必须提供，缺失即 fail closed
}
```

注意：

- 用户身份在同一个授权域内必须唯一。
- 不同租户是否允许相同 subject_id，由租户模块定义。
- 不允许通过未验证的 HTTP 参数直接指定 subject_id。
- 身份必须来自业务项目已完成认证的可信上下文。

## 4.3 授权服务接口

```go
type Authorizer interface {
    HasPermission(
        ctx context.Context,
        ac AuthorizationContext,
        permission string,
    ) (bool, error)

    HasAnyPermission(
        ctx context.Context,
        ac AuthorizationContext,
        permissions ...string,
    ) (bool, error)

    HasAllPermissions(
        ctx context.Context,
        ac AuthorizationContext,
        permissions ...string,
    ) (bool, error)

    GetPermissions(
        ctx context.Context,
        ac AuthorizationContext,
    ) ([]string, error)

    IsSuperAdministrator(
        ctx context.Context,
        ac AuthorizationContext,
    ) (bool, error)
}
```

授权服务必须区分：

- 正常无权限（返回 false, nil）。
- 权限查询失败（返回 false, err，不得视为授权成功）。
- 用户身份无效。
- 用户账号禁用（经 SubjectStatusChecker 集成时）。

超级管理员语义（方向已定，细节待细化）：

- `HasPermission` / `HasAny` / `HasAll` 对超级管理员恒真，但仍受账号状态与租户边界约束。
- `GetPermissions` 对超级管理员返回空集合；前端应以 `IsSuperAdministrator` 单独判断，避免引入通配符语义。

查询错误不能被当成授权成功。

## 4.4 身份解析与账号状态接口

业务项目负责提供身份解析器：

```go
type SubjectResolver interface {
    Resolve(ctx context.Context) (SubjectID, error)
}
```

账号状态检查（可选注入）：

```go
type SubjectStatusChecker interface {
    IsSubjectActive(ctx context.Context, subjectID SubjectID) (bool, error)
}
```

- 账号状态由业务系统持有，RBAC 不存储。
- 检查返回 false → 拒绝（403）；检查返回 error → fail closed（500）。
- 多租户启用后，租户 ID 由 tenant 模块定义的 TenantResolver 从可信上下文解析，规则同 SubjectResolver。

框架适配器通过业务项目提供的 Resolver 获取身份，不应强制规定 JWT Claims 或 Context Key 的具体名称。

## 4.5 缓存接口

```go
type PermissionCache interface {
    Get(
        ctx context.Context,
        key string,
    ) ([]string, bool, error)

    Set(
        ctx context.Context,
        key string,
        permissions []string,
        ttl time.Duration,
    ) error

    Delete(
        ctx context.Context,
        key string,
    ) error
}
```

基础模块提供 NoopCache，Redis 作为独立适配器。缓存 key 的构造规则由 Core 统一负责（见 §6.1）。

## 4.6 观测接口（可选）

```go
type Metrics interface {
    DenialsInc(reason string) // 401 / 403 / 500 拒绝计数
    AuthorizeObserved(cacheHit bool, d time.Duration)
}
```

- 默认提供 NoopMetrics。
- 不强制绑定 Prometheus 等具体实现，业务项目自行适配。

## 4.7 内置管理权限码

库内置注册一组自身管理权限码，用于保护 RBAC 管理接口：

```text
rbac:role:list / rbac:role:create / rbac:role:update / rbac:role:delete
rbac:role:assign        // 角色权限分配
rbac:user:assign-role   // 用户角色分配
rbac:grant:create / rbac:grant:revoke
rbac:permission:sync    // 权限同步与清理
rbac:audit:read         // 审计查询（Audit 模块）
```

规则：

- 普通管理员不得授予他人 `rbac:*` 权限，除非自身持有（与 §2.2 授权者约束配合）。
- 业务项目用同一套中间件保护 RBAC 管理接口。

---

# 五、数据库模型设计（v1 冻结稿）

## 5.1 全局约定

| 项 | 约定 |
|---|---|
| 基准 | MySQL 8.0+，InnoDB，`utf8mb4 / utf8mb4_0900_ai_ci`（5.7 需确认 DYNAMIC row format） |
| 主键 | `BIGINT UNSIGNED AUTO_INCREMENT`（Go 侧 uint64；不用复合主键，GORM 友好） |
| 时间 | `DATETIME(3)`，应用层统一 UTC；DSN `parseTime=true&loc=UTC`；不使用 TIMESTAMP（2038 + 隐式时区换算） |
| 软删除 | **全库无 deleted_at**；管理对象用 `status`，关联关系物理删除，生命周期只保留在 user_grants 表 |
| 表前缀 | v1 固定 `rbac_`（可配置前缀列入后续版本评估：前缀可配则 SQL 迁移需模板替换，v1 不背此复杂度） |
| 外键 | 不建立指向外部用户表的外键；库内关联以唯一约束 + 服务层保证 |
| 租户列 | v1 无 tenant_id；tenant 模块迁移契约见 §2.9 / §5.5 |

## 5.2 基础表 DDL（五张核心表）

```sql
CREATE TABLE rbac_roles (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code        VARCHAR(64)  NOT NULL COMMENT '角色代码，授权域内唯一；启用租户后唯一键变为(tenant_id, code)',
    name        VARCHAR(128) NOT NULL COMMENT '展示名',
    description VARCHAR(255) NOT NULL DEFAULT '',
    is_builtin  TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '1=内置受保护角色(如超管载体)，禁止删除/禁用',
    status      TINYINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '1=启用 0=禁用',
    created_at  DATETIME(3) NOT NULL,
    updated_at  DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE rbac_permissions (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code        VARCHAR(128) NOT NULL COMMENT '权限码，全局唯一且稳定，格式 模块:操作',
    name        VARCHAR(128) NOT NULL,
    module      VARCHAR(64)  NOT NULL COMMENT '分组展示用',
    description VARCHAR(255) NOT NULL DEFAULT '',
    status      TINYINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '1=启用 0=禁用 2=已废弃(代码不再注册)',
    created_at  DATETIME(3) NOT NULL,
    updated_at  DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_code (code),
    KEY idx_module (module)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 纯关联表：撤销即物理删除，历史由 Audit 模块负责
CREATE TABLE rbac_user_roles (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    subject_id VARCHAR(128) NOT NULL COMMENT '外部用户标识，非本库外键',
    role_id    BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_subject_role (subject_id, role_id),
    KEY idx_role (role_id)  -- 反查：角色→用户（批量失效 fan-out 查询）
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE rbac_role_permissions (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    role_id       BIGINT UNSIGNED NOT NULL,
    permission_id BIGINT UNSIGNED NOT NULL,
    created_at    DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_role_permission (role_id, permission_id),
    KEY idx_permission (permission_id)  -- 反查：权限→角色（禁用前检查、失效判断）
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 唯一保留完整生命周期的表：撤销/过期记录不删，服务审计
CREATE TABLE rbac_user_grants (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    subject_id    VARCHAR(128) NOT NULL,
    permission_id BIGINT UNSIGNED NOT NULL,
    expires_at    DATETIME(3) NULL COMMENT 'NULL=永久；缓存TTL不得超过最近到期时间',
    reason        VARCHAR(255) NOT NULL DEFAULT '',
    created_by    VARCHAR(128) NOT NULL COMMENT '操作人 subject_id',
    created_at    DATETIME(3) NOT NULL,
    revoked_at    DATETIME(3) NULL,
    revoked_by    VARCHAR(128) NULL,
    active_flag   TINYINT GENERATED ALWAYS AS (IF(revoked_at IS NULL, 1, NULL)) STORED
                  COMMENT '撤销行为NULL，不参与唯一约束；兜底防重复活跃授权',
    PRIMARY KEY (id),
    UNIQUE KEY uk_subject_permission_active (subject_id, permission_id, active_flag),
    KEY idx_permission (permission_id),  -- 反查：权限→被授用户（失效 fan-out）
    KEY idx_expires (expires_at)         -- 到期扫描/审计
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```

## 5.3 生命周期策略

- `rbac_user_roles`、`rbac_role_permissions` 是纯关联表：**撤销即物理删除**。原因：MySQL 无部分索引，"同一对关联只允许一条有效记录"在保留历史行的表上无法用普通唯一索引表达；历史责任归 Audit 模块。
- `rbac_user_grants` 是唯一保留完整生命周期的表（产品要求撤销/过期记录可审计）。
- `rbac_roles` / `rbac_permissions` 用 `status` 表达启用/禁用/废弃，不做物理删除的前置检查（删除角色需检查关联关系后硬删，并在同一事务清理关联行）。
- `active_flag` 生成列**是兜底不是主防线**：MySQL 生成列不能使用 `NOW()`，"已过期但未撤销"的行 active_flag 仍为 1。主防线是服务层事务：新授权前先撤销冲突的未撤销行（含已过期），再插入。GORM 模型中该列只读，由数据库生成。

## 5.4 索引设计说明

- `uk_subject_role` 把 subject_id 放最左：**"取某用户的角色"是每次鉴权的热路径**；`idx_role` 服务反查（角色→用户，缓存失效 fan-out）。
- `idx_permission` 两处：权限→角色（禁用前检查）、权限→被授用户（失效 fan-out）。
- `uk_subject_permission_active` 最左前缀即 subject_id，可复用于 subject 维度查询，无需单独 idx_subject。
- 删除任何反查索引前，先核对 §6.3 失效矩阵的 SQL 依赖。

## 5.5 租户前向兼容契约

v1 无 tenant_id 是刻意决策（永不启用多租户的项目不付成本），已接受代价：tenant 模块迁移必须完成 **加列（默认空串 = default 域）→ 存量回填 → 重建三个唯一键**（清单见 §2.9）。唯一键重建是其中最疼的一步，该迁移路径的测试是 tenant 模块第一验收项。

## 5.6 高级模块表（由各模块迁移贡献）

| 表名 | 用途 | 贡献模块 |
|---|---|---|
| rbac_role_templates / rbac_role_template_permissions | 角色模板 | template |
| rbac_menus / rbac_menu_permissions | 菜单 | menu |
| rbac_role_data_scopes | 数据范围（枚举型） | datascope |
| rbac_audit_logs | 授权审计 | audit |
| （加列 + 唯一键重建，不新建表） | 租户 | tenant |

## 5.7 数据库迁移机制

- **版本化 SQL 文件 + `io/fs` embed + `schema_migrations` 版本表**；`app.Migrate(ctx)` 按 Core → 模块注册顺序执行未应用版本。
- 不将 GORM AutoMigrate 作为生产迁移方案（仅可用于开发期）。
- MySQL 的 DDL 存在隐式提交：**多语句迁移在 MySQL 上不是原子的**（8.0 仅保证单条 DDL 原子），因此迁移步骤要小、可重入。
- 迁移执行权在业务项目：可自行决定时机、在发布流程统一执行、或使用自己的迁移工具调用库内嵌的 SQL。

---

# 六、缓存与一致性设计

> 权限缓存不是普通缓存：失效机制出错，就可能出现"已撤销的权限仍然可用"。本章是全库最需要认真对待的部分。
>
> 定位声明（v0.4.0-design 起）：**版本号权威来源是数据库**。Redis 只缓存权限集合与版本号副本；TTL 是垃圾回收机制，不承担正确性。

## 6.1 缓存内容与 Key

缓存用户**最终有效权限集合**（不缓存中间查询）。Key 格式（scope 槽位 v1 定死，多租户上线只改取值不改形状）：

```text
rbac:{scope}:epoch                          # 授权域 epoch 副本（权威值在数据库）
rbac:{scope}:subject:{subject_id}:version   # 主体权限版本号副本（权威值在数据库）
rbac:{scope}:subject:{subject_id}:perm:v{generation}
```

单租户模式 `scope = default`；多租户模式 `scope = {tenant_id}`。
`generation = epoch<<32 | subject_version`（两计数器合并进单一生成键）。

**权威计数器存储**（迁移 0002）：数据库表 `rbac_counters(k, v)`，键与 Redis 键同构：
`{scope}:epoch`、`{scope}:subject:{subject_id}:version`。

## 6.2 版本号机制（数据库权威）

**核心不变性（承重墙，以代码强制）：**

> 1. 权威版本号与授权变更在**同一数据库事务**内提交（变更即递增，原子）。
> 2. Redis 计数器是权威值的**忠实副本**：任何写入路径只能写"从数据库读到的真实值"，
>    且**只允许单调前进**（SetIntMax 原语），永不回退、永不相对递增。

**读取流程：**

1. 读取 Redis 的 epoch 与版本号副本，得到生成键 G。
2. 副本缺失 / 损坏 / Redis 故障 → **从数据库读取权威值**并以 SetIntMax 回填副本
   （回填的是真实版本而非重置归零——不存在"重建值碰撞历史生成键"问题），
   随后照常继续。
3. 读取 `perm:v{G}`；命中直接返回。
4. 未命中 → singleflight 合并并发回源 → **查询数据库（主库，见 6.4）**。
5. 写回前复核生成键未变（副本可读则比副本；副本不可读则以 DB 权威值比较）；
   已变则丢弃结果重走流程（一次重试，仍不稳定返回未缓存数据——正确性不受影响）。

**写入流程（授权变更）：**

1. 数据库事务：变更授权数据 + **同事务递增权威计数器**（UPSERT 自增）。
2. 提交。
3. 同步 Redis 副本：读权威真值 → SetIntMax 单调写回。
4. 同步任一步失败 → **删除该副本**（迫使后续读回退数据库权威值）→ 管理接口
   返回 `ErrInvalidationFailedAfterCommit`（重试语义按操作分级，见 README）。

**禁止模式**（每一项都曾造成真实缺陷，外部评审五轮收敛）：

| 禁止 | 缺陷 |
|---|---|
| 副本 INCR（相对递增） | 副本被删后从 1 重建，与权威持久偏差，读者无法察觉 |
| 无条件 SET / SetInt | 恢复（真值 10）与更新同步（真值 11）乱序并发时副本回退 |
| SETNX 0 重建基线 | 重建值与历史生成键碰撞，旧权限复活 |

## 6.3 失效矩阵

| 变更操作 | 失效方式 | 粒度 |
|---|---|---|
| 用户角色变更 | 该主体 subject version（同事务递增） | 精确 |
| 用户额外授权 / 撤销 / 到期 | 该主体 subject version（同事务递增） | 精确 |
| 角色权限变更 | 授权域 epoch（同事务递增） | 全域 |
| 角色禁用 / 删除 | 授权域 epoch（同事务递增） | 全域 |
| 权限禁用 / 启用 | 授权域 epoch（同事务递增） | 全域 |
| 权限同步（有差量） | 授权域 epoch（同事务递增） | 全域 |

**两级失效机制：**

- **精确级**（subject version）：用户级变更，影响面明确，只失效该主体。
- **粗糙级**（epoch）：角色级 / 权限级变更。一次角色权限修改使整个授权域
  （单租户 = default 域；多租户 = 该租户域）权限缓存冷启动。
  **这是刻意的性能取舍而非正确性问题**：角色级变更是低频管理操作，
  消除逐用户 fan-out 的部分成功窗口（30/100 用户失效成功、70 个未失效）
  换取一次全域冷启动，对典型 DevOps 平台完全可接受。
  升级触发条件：单域缓存规模使冷启动代价不可接受时，引入角色级版本号（v2+）。

## 6.4 并发与主从一致性

**写前复核**：缓存回填前复核生成键（6.2 读流程第 5 步），防止旧数据写入当前生成键。

**主从分离：**

- 权威版本号在数据库。若业务项目读写分离、缓存 miss 回源打到**延迟的从库**，
  可能聚合到提交前的旧权限，且从库中的权威计数器同样滞后——写回复核
  （以主库权威值或已同步副本比较）会拦截绝大多数场景，但从库计数器滞后的
  极端窗口无法完全自愈。
- 规则：**缓存回填路径必须读主库**（v1 强制；缓存 miss 时的聚合查询与
  副本恢复的权威读取均含在内）。

## 6.5 临时授权过期

用户额外授权支持 expires_at。必须确保权限缓存不会在临时授权到期后继续放行：

- 缓存 TTL 不超过该用户最近一条授权的到期时间。
- 查询层始终校验 expires_at（缓存中的集合与 DB 查询同样受约束）。
- 后续增强：定时任务扫描到期授权，主动递增权威版本并同步副本（v2+）。

## 6.6 故障语义

| 故障 | 行为 |
|---|---|
| Redis 副本同步失败 | **正确性不受影响**：删除该副本 → 后续读回退数据库权威值；管理接口返回 `ErrInvalidationFailedAfterCommit`（按操作分级的重试语义） |
| Redis 整体故障 | **鉴权**：回源数据库（权威值 + 授权数据均在主库）。**管理接口**：变更照常提交（权威计数器同事务递增），仅副本同步失败报错——重试安全 |
| 计数器副本丢失/损坏（淘汰、误配 allkeys-*） | 读路径从数据库回填权威值（SetIntMax 单调写，自愈），不产生旧权限复活 |
| 数据库故障 | Fail Closed，拒绝访问 |

## 6.7 一致性边界声明

明确声明本库的一致性语义，不留给使用者猜：

1. **正常运行**：授权变更与权威版本递增原子提交；副本同步在提交后尽力完成。
   同步失败不影响正确性（副本被删、读路径回退权威值），仅影响该主体的缓存命中率。
2. **已知窗口**：
   - 提交 → 副本同步完成之间（毫秒级），其他实例的旧副本可能短暂返回变更前的
     缓存条目——由"管理接口返回成功前完成同步"约束在服务端关闭，极端并发下
     以变更可见性毫秒级延迟为上界。
   - Redis 主从异步复制窗口（通常毫秒级，由 Redis 部署决定）。
3. **明确不提供**：跨缓存层的严格线性一致。业务要求更强的即时生效语义
   （如金融级撤销）需在未来版本引入请求期权威校验。
4. **Outbox（后续增强）**：解决的是"副本同步失败时的管理接口可用性与审计
   原子性"，不是正确性——正确性已由数据库权威版本保证。

## 6.8 第一版缓存实现范围

| 机制 | 状态 |
|---|---|
| 用户权限缓存 + 生成键 | 支持 |
| 数据库权威计数器（同事务递增） | 支持（迁移 0002） |
| 副本同步 = 读真值 + SetIntMax 单调写 | 支持 |
| 副本恢复（丢失/损坏 → DB 回填 + 自愈） | 支持 |
| 两级失效（subject version / epoch） | 支持（角色级全部走 epoch） |
| 缓存回填数据源 | 主库 |
| 临时授权到期 | TTL 约束 + 查询时校验 |
| 缓存击穿防护（singleflight） | 支持 |
| Redis 故障 | 鉴权回源 DB；管理接口报哨兵（重试分级） |
| 数据库故障 | Fail Closed |
| 副本同步失败的 Outbox 补偿 | 后续增强（可用性，非正确性） |
| 角色级版本号（消除全域冷启动） | 后续增强（性能，触发条件见 6.3） |
| 审计事件同事务 Outbox | 后续增强（见 docs/phase3-evaluation.md） |

# 七、安全设计

## 7.1 默认拒绝

所有需要保护的 API 默认要求明确声明权限。

未声明权限的公开接口必须由业务项目明确管理，不能因为未配置权限而自动获得保护接口的访问权。

## 7.2 失败关闭

以下情况一律不能放行：

- 数据库查询失败。
- Redis 缓存异常且无法回源。
- 用户身份解析失败。
- 账号状态检查失败（SubjectStatusChecker 返回 error）。
- 权限注册数据不一致。
- 租户上下文缺失（启用多租户后，TenantID 缺失即拒绝）。

## 7.3 超级管理员

超级管理员采用**独立、受保护的授权机制**（方向已定，细节待细化）：

- 载体：内置受保护角色（`rbac_roles.is_builtin = 1`，code 如 `super_admin`），仅能通过初始化种子或配置创建；管理接口不可授予、撤销、删除、禁用该角色。
- 判定：`Authorizer.IsSuperAdministrator`；对 HasPermission 系列恒真。
- 边界：超级管理员仍受账号状态、租户边界、平台/租户管理边界、业务数据安全规则约束。
- 不引入通配符：`GetPermissions` 对超管返回空集合，前端以 `IsSuperAdministrator` 单独判断。
- 不能简单地将普通角色命名为 admin 后绕过全部鉴权。

## 7.4 授权管理保护

普通管理员不能随意：

- 给自己提升超级管理员权限。
- 创建未知权限资源（只能引用 Registry 已注册权限）。
- 修改权限 Code。
- 授予自己不持有的权限（§2.2 授权者约束，默认开启）。
- 授予或获取 `rbac:*` 管理权限（除非已持有）。
- 跨租户授权。
- 删除仍被使用的角色（删除前检查关联关系）。
- 删除或禁用内置受保护角色。
- 绕过授权审计。

---

# 八、开发路线图

## Phase 1：核心 RBAC

目标：完成真正可用的基础权限库。

任务：

- [ ] 项目初始化。
- [ ] 基础数据库模型（§5 冻结稿）。
- [ ] GORM Repository。
- [ ] 版本化 SQL Migration + embed。
- [ ] Permission Registry（含权限码格式校验）。
- [ ] 权限同步机制。
- [ ] 角色管理（含 is_builtin 保护）。
- [ ] 用户角色关联。
- [ ] 角色权限关联。
- [ ] 用户额外授权（含生命周期事务语义）。
- [ ] Authorization Service（含 IsSuperAdministrator）。
- [ ] Gin Middleware（含错误响应定制）。
- [ ] 用户身份解析接口 + 账号状态检查接口。
- [ ] 启动期权限码交叉校验。
- [ ] 内置 rbac:* 管理权限码。
- [ ] Module Registry（注册/依赖检查/迁移收集）。
- [ ] 无缓存实现（NoopCache）。
- [ ] 单元测试和集成测试。

验收标准：

新建一个 Gin 项目，只需要引入 go-rbac、配置数据库、声明权限资源、完成身份解析，即可实现基础 API 鉴权和角色授权。

## Phase 2：缓存与管理能力

目标：完善性能和管理能力。

任务：

- [ ] Redis Adapter。
- [ ] 权限缓存（版本号 + epoch 两级失效）。
- [ ] 批量失效与失效矩阵全覆盖测试。
- [ ] 缓存击穿防护（singleflight）。
- [ ] 临时授权过期处理。
- [ ] 角色模板。
- [ ] 权限批量操作。
- [ ] 授权变更审计（Audit 模块，承接关联表历史）。
- [ ] 观测埋点（Metrics 接口落地）。
- [ ] 性能基线测试（§9.4）。

## Phase 3：高级权限模块

目标：支持更复杂的后台业务。

任务：

- [ ] Menu 模块。
- [ ] Data Scope 模块（四种枚举范围，取最宽合并）。
- [ ] Multi-Tenant 模块（**第一验收项 = §5.5 迁移契约测试**）。
- [ ] CUSTOM 数据范围与组织架构扩展接口评估。
- [ ] 更多框架适配器。
- [ ] Outbox 补偿机制评估。

## Phase 4：稳定性与生态

目标：使其成为可以长期复用的基础组件。

任务：

- [ ] 完整 API 文档。
- [ ] 接入示例。
- [ ] 数据库兼容性测试（MySQL 8.0 基准，5.7 评估）。
- [ ] 并发授权测试。
- [ ] 缓存一致性测试（含主从延迟场景）。
- [ ] 安全测试。
- [ ] Go 版本兼容性测试。
- [ ] pkg.go.dev 命名查重与定名。
- [ ] 版本发布规范、CHANGELOG、CI 自动化测试。

---

# 九、测试与质量要求

## 9.1 单元测试

重点覆盖：

- 多角色权限并集。
- 用户额外授权。
- 临时授权过期。
- 权限不存在。
- 禁用角色 / 禁用权限。
- 权限注册幂等与格式校验（拒绝通配符）。
- 缓存失效矩阵逐行覆盖。
- 版本号机制：提交/递增并发竞态、写前复核。
- epoch 全局失效。
- 授权者持权约束。

## 9.2 集成测试

使用真实 MySQL / Redis 或容器化测试环境验证：

- 数据库迁移（含 tenant 迁移契约路径，Phase 3）。
- 用户角色关联。
- 角色权限变更与批量失效。
- Redis 缓存读写与版本递增。
- 授权变更后的缓存一致性。
- 并发授权变更。
- 主从延迟场景（或以配置约束 + 文档声明兜底）。
- 多租户隔离（模块启用后）。

## 9.3 安全测试

重点验证：

- 无权限不能访问。
- 身份解析失败不能放行。
- 账号状态检查失败不能放行。
- 数据库异常不能放行。
- Redis 异常不能放行。
- 额外授权不能绕过租户隔离。
- 用户不能通过参数伪造 subject_id。
- 普通管理员不能越权授予权限（含 rbac:* 与超管角色）。
- 内置受保护角色不可经管理接口修改。

## 9.4 性能基线（准入基线而非 SLA）

| 指标 | 目标 |
|---|---|
| 缓存命中路径 HasPermission | P99 < 1ms（不含框架开销） |
| 冷路径权限聚合（1k 权限规模） | P99 < 50ms |
| 角色权限变更批量失效（1k 用户） | < 100ms |
| 权限同步（500 权限幂等重跑） | < 2s |

---

# 十、产品交付标准

第一版发布前，至少需要具备：

1. 可通过 `go get` 安装。
2. 提供基础 GORM 数据模型（§5 冻结稿）。
3. 提供版本化 SQL 迁移能力。
4. 提供权限资源注册与同步（含格式校验）。
5. 提供角色管理接口（含内置角色保护）。
6. 提供用户角色分配接口。
7. 提供角色权限分配接口。
8. 提供用户额外授权接口（含撤销与到期）。
9. 提供统一授权服务（含 IsSuperAdministrator）。
10. 提供 Gin 鉴权中间件（含错误响应定制、启动期权限码校验）。
11. 支持不使用 Redis。
12. 提供完整的 Gin 接入示例。
13. 提供基础测试和使用文档。

最终使用体验：

```go
app, err := rbac.New(
    rbac.WithDB(db),
    rbac.WithPermissionRegistry(registry),
)

if err != nil {
    panic(err)
}

if err := app.Migrate(ctx); err != nil {
    panic(err)
}

if err := app.SyncPermissions(ctx); err != nil {
    panic(err)
}

auth := app.Authorizer()
guard := ginadapter.New(auth, resolver)

api.GET(
    "/users",
    guard.Require("user:list"),
    userController.List,
)
```

业务项目只需要：

- 提供用户认证。
- 提供用户身份解析。
- 声明业务权限。
- 配置 RBAC。
- 在业务接口中声明所需权限。

其余权限管理基础能力由 go-rbac 提供。

---

# 十一、决策记录

以下事项已定案（原"待决策事项"表随 v0.3.0 定稿转为决策记录）：

| 事项 | 结论 | 状态 |
|---|---|---|
| Web 框架 | 核心无框架依赖，Gin 优先适配 | 已确定 |
| ORM | GORM 默认实现 | 已确定 |
| 用户 ID | SubjectID string，VARCHAR(128) | 已确定 |
| Redis | 可选 Adapter | 已确定 |
| 多租户 | v1 无 tenant_id + Scope 预留 + 迁移契约 | 已确定（模块细节待细化） |
| 数据权限 | 四种枚举范围取最宽合并；CUSTOM 延后 | 已确定（CUSTOM 于 datascope 模块阶段设计） |
| 角色继承 | 第一版不做 | 已确定 |
| 显式 Deny | 不支持 | 已确定 |
| 通配符权限 | v1 不支持，按字面匹配 | 已确定 |
| 用户额外授权 | 支持，含完整生命周期 | 已确定 |
| 角色模板 | 复制模式 | 已确定 |
| 菜单关联权限 | 可选关联 | 已确定 |
| 数据库迁移 | 版本化 SQL + embed，业务项目控制执行 | 已确定 |
| 表名自定义 | v1 固定 `rbac_` 前缀 | 已确定（可配置前缀列入后续版本评估） |
| 超级管理员 | 内置受保护角色 + IsSuperAdministrator | 方向已定，细节待细化 |
| 多租户身份域 | tenant_id 与 subject_id 组合 | 待细化（tenant 模块阶段） |
| 缓存回填数据源 | 主库 | 已确定 |
| 缓存失效 | 版本号 + 全局 epoch 两级机制 | 已确定 |
| Outbox | v2+，可用性增强而非一致性 | 已确定 |
| Casbin Adapter | 不纳入路线图 | 已确定 |
| 授权者持权约束 | 默认开启，可配置关闭 | 已确定 |
| Authorizer 签名 | 接受 AuthorizationContext | 已确定 |
| Repository 接口可见性 | v1 保持内部，公开 API 面最小化 | 已确定 |

仍在细化中的事项（不阻塞 v1 开发，按所属模块阶段收口）：

- 超级管理员的种子初始化与配置细节（§7.3）。
- 多租户模块内部设计（用户多租户归属、平台角色表达、TenantResolver）。
- CUSTOM 数据范围的存储与运算模型（datascope 模块）。
- 菜单 AND 语义的触发条件（menu 模块）。

---

# 十二、最终产品愿景

go-rbac 不追求成为一个功能繁杂的 IAM 平台，而是成为 Go 后台开发中可靠、轻量、易接入、可扩展的权限基础组件。

希望最终实现：

**一次设计，多项目复用；基础功能开箱即用，高级功能按需启用；业务项目只关心业务，不再重复造权限系统。**
