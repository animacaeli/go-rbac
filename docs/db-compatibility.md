# 数据库兼容性说明

对应设计文档 §3.2（MySQL 8.0+ 为第一版主要支持）与 §8 Phase 4
“数据库兼容性测试（MySQL 8.0 基准，5.7 评估）”。

## 支持矩阵

| 版本 | 状态 | 验证方式 |
|---|---|---|
| MySQL 8.0 | **基准**（设计冻结） | CI 集成测试（每次 push/PR） |
| MySQL 8.4（LTS） | 支持 | CI 集成测试矩阵 |
| MySQL 5.7 | **不支持**（评估结论，见下） | — |

CI 矩阵见 `.github/workflows/ci.yml` 的 `integration` job
（`strategy.matrix.mysql: [8.0, 8.4]`），两版本各跑全套集成、一致性、
租户契约与安全套件。

## MySQL 5.7 评估结论：不投入

逐一核对 v1 冻结 DDL（§5.2）与 5.7 的能力差异：

| 项 | 8.0 | 5.7 | 影响 |
|---|---|---|---|
| `utf8mb4_0900_ai_ci` 排序规则 | 有 | **无**（仅 `utf8mb4_general_ci` / `unicode_ci`） | 硬阻塞：全部 DDL 显式使用该 collation |
| 生成列 `IF(...) STORED` | 支持 | 支持 | 无阻塞 |
| `DATETIME(3)` | 支持 | 支持 | 无阻塞 |
| DDL 原子性 | 单条 DDL 原子 | 无 | §5.7 已按"步骤小、可重入"设计规避 |
| DYNAMIC row format | 默认 | 需显式确认 | 设计文档 §5.1 已标注 |

支持 5.7 需要为 collation 引入 DDL 模板替换（v1 明确不背此复杂度，
§5.1“表前缀可配推迟”同理由），且 5.7 已于 2023-10 结束官方支持。
**结论：不支持，不计划支持**；如有真实存量 5.7 需求再评估 fork DDL 的成本。

## 对使用者的部署要求

- 字符集/排序规则无需配置：全部表 DDL 显式指定 `utf8mb4 / utf8mb4_0900_ai_ci`，
  与服务器默认值无关；身份列（`rbac_user_roles.subject_id`、
  `rbac_user_grants.subject_id`）在迁移 0004、`rbac_counters.k` 在迁移 0003
  改为 `utf8mb4_0900_bin`（身份按二进制比较），依赖 MySQL 8.0 的 0900
  排序规则家族
- 时间语义：`DATETIME(3)` + 应用层 UTC，DSN 必须
  `parseTime=true&loc=UTC`（§5.1）
- 读写分离部署：**权限回填路径必须读主库**（§6.4；§9.2 以配置约束 +
  文档声明兜底）。将 `rbac.WithDB` 指向主库连接即可满足
