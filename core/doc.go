// Package core 实现与框架无关的授权核心：授权上下文、统一授权服务、
// 授权变更事件与管理服务。
//
// 本包是 go-rbac 的运行时心脏，职责划分：
//
//   - 上下文与身份契约：SubjectID、AuthorizationContext（授权域显式化，§4.2）、
//     SubjectResolver / SubjectStatusChecker（业务实现注入）
//   - AuthorizationService（§4.3/§6）：统一授权判断。缓存一致性由
//     生成键（epoch<<32|version 组合进 §6.1 的 perm key）、写前复核、
//     singleflight 击穿防护与"提交后才递增版本"的不变性共同保证；
//     失效操作（IncrSubjectVersion/IncrEpoch）按 ctx 授权域递增
//   - 管理服务：RoleService / UserRoleService / GrantService /
//     PermissionService，统一执行"注册校验 → 授权者持权约束 → 落库 →
//     版本递增 → 审计事件"链路；operator 的 TenantID 经
//     ContextWithTenant 注入 ctx 供租户隔离仓储使用
//   - EventBus（§2.10）：授权变更事件分发给 Audit 模块等实现
//
// 本包不依赖任何 Web 框架与 Redis 客户端；缓存经 cache.PermissionCache
// 抽象注入（默认 NoopCache，每次回源数据库）。
package core
