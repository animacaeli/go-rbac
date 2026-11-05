-- 0002_counters: 数据库权威版本号（外部审核第三轮 P0-1 第一阶段）
-- 授权变更与版本递增在同一事务提交（§6.2 不变性的权威来源）；
-- Redis 计数器降级为该权威值的缓存副本（丢失/损坏 → 从本表回填，而非重置归零，
-- 结构上消除"重建值与历史生成键碰撞"这一类问题）。
-- 键与 Redis 键后缀同构："{scope}:epoch" / "{scope}:subject:{id}:version"。
CREATE TABLE IF NOT EXISTS rbac_counters (
    k          VARCHAR(191) NOT NULL COMMENT '计数器键：{scope}:epoch 或 {scope}:subject:{id}:version',
    v          BIGINT       NOT NULL DEFAULT 0,
    updated_at DATETIME(3)  NOT NULL,
    PRIMARY KEY (k)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
