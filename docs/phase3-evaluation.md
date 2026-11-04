# Phase 3 评估记录：CUSTOM 数据范围 / 组织架构扩展接口 / Outbox

对应设计文档（docs/go-rbac-design.md）§8 Phase 3 的两项"评估"任务。
本文件记录评估结论与触发条件，作为后续版本的决策依据。

## 一、CUSTOM 数据范围与组织架构扩展接口

**结论：维持 §2.8 冻结决策，延后实现；接口形状预留如下。**

理由：

1. **存储模型未定**：CUSTOM 需要自定义集合（如部门 ID 集合）的存储表
   （`rbac_role_data_scope_custom`），涉及 JSON 集合 vs 关系行的取舍；
   在语义未定义清楚前引入会冻结错误形状（v0.3.0-design 修订记录的立场）。
2. **真正的并集运算**：枚举范围"取最宽"在数学上等价于并集（§2.8 已论证）；
   CUSTOM 集合之间需要真正的集合运算（并集/包含判断），其缓存失效语义
   （集合变更如何影响各主体）也需独立设计，复杂度与收益不匹配当前阶段。
3. **组织关系归属业务**：部门树、兼职、虚拟组织等结构因项目而异，
   库内固化模型反而限制接入。

预留接口形状（实现时落地于 datascope 模块，业务侧先行按此抽象准备）：

```go
// DepartmentResolver 由业务项目实现：提供组织关系查询。
// RBAC 不存储组织架构（§2.8：业务项目负责组织关系与字段映射）。
type DepartmentResolver interface {
    // DepartmentsOf 返回主体所属部门（含兼职等多归属）。
    DepartmentsOf(ctx context.Context, subjectID SubjectID) ([]string, error)
    // DepartmentChildren 返回部门的直接下级。
    DepartmentChildren(ctx context.Context, departmentID string) ([]string, error)
}

// ResolveDataScope 返回值的扩展形态（示意）：
//   ScopeCustom{DepartmentIDs []string}  // 已解析的可见部门集合
```

**触发条件**：出现真实业务需要"跨部门指定集合"授权（如区域经理管辖
非连续区域），且能给出缓存失效语义的验收测试时启动。

## 二、Outbox 补偿机制

**结论：维持 §6.7 定位——Outbox 是可用性增强而非一致性问题，延后。**

当前状态（已实现并测试覆盖）：

- 一致性由"事务提交 → 版本/epoch 递增 → 成功后才向管理接口返回成功"保证；
- 递增失败时管理接口整体报错，不出现半成功状态（§6.7 已知窗口）；
- 代价：Redis 故障期间权限管理不可用（可用性换一致性，刻意选择，已文档化）。

Outbox 方案草图（触发后实现）：

1. 授权变更事务内同时写入本地 outbox 表（目标：递增操作清单）；
2. 后台投递器轮询 outbox，向 Redis 执行 INCR 并标记完成；
3. 投递幂等（INCR 天然可重放需配合"至少一次 + 去重水位"）；
4. 管理接口在 Redis 故障期间返回成功（数据库已提交 + outbox 已记录），
   撤销生效延迟 = 故障时长，需在文档与告警中显式声明。

**触发条件**：Redis 故障期间"权限管理不可用"成为生产痛点
（监控指标：invalidation 失败率 / 管理接口 5xx），且业务接受
"撤销延迟到 Redis 恢复"的语义时启动。在此之前，现有语义更安全。

## 三、Phase 3 落地情况备注

- Menu / DataScope / Multi-Tenant（含 §5.5 迁移契约验收）已实现；
- 适配器新增 net/http（标准库零依赖）；Fiber / Echo 维持 §3.4 立场
  （按实际需求逐步实现，逃生舱结构已由 gin / http 双实现验证）。
