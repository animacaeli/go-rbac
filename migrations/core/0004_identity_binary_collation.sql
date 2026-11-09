-- 0004_identity_binary_collation: 身份标识与计数器键改为二进制排序规则。
--
-- 背景：库表此前统一使用 utf8mb4_0900_ai_ci（忽略大小写与重音）。subject_id
-- 是外部不透明标识，不应继承数据库语言排序规则的等价关系——否则 MySQL 认为
-- 相等的两个标识在 Redis 缓存键上仍是两个不同字符串，撤销只同步其中一个
-- 缓存域，另一个会保留旧权限直到 TTL（第八轮复审 P1-03）。
--
-- utf8mb4_0900_bin 是 NO PAD 二进制比较（MySQL 8.0.17+）。MODIFY 到相同
-- 定义可重复执行；唯一键随列排序规则重建，之后大小写/重音不同的标识是
-- 不同主体（行为变更，见 CHANGELOG「API 调整」）。
ALTER TABLE rbac_user_roles
    MODIFY COLUMN subject_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL;

ALTER TABLE rbac_user_grants
    MODIFY COLUMN subject_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL;

-- 权威计数器键同样按字节比较：{scope}:subject:{subject_id}:version 中的
-- subject_id 必须与身份标识一一对应，否则不同主体会共享同一个权威版本。
ALTER TABLE rbac_counters
    MODIFY COLUMN k VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL
    COMMENT '计数器键：{scope}:epoch / {scope}:subject:{id}:version / !global:epoch';
