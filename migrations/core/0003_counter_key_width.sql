-- 0003_counter_key_width: 计数器键列宽与授权到期索引。
--
-- 1) rbac_counters.k 原为 VARCHAR(191)，但主体版本键最长可达
--    "{tenant(64)}:subject:{subject(128)}:version" ≈ 209 字符，长租户 + 长主体
--    在严格模式下会触发 1406（Data too long），使整个授权变更事务回滚。
--    MODIFY 到相同定义可重复执行，天然幂等。
-- 2) 授权到期查询（subject_id + revoked_at + expires_at）缺少覆盖索引；
--    用 information_schema 判断 + 动态 DDL 保证可重入。

ALTER TABLE rbac_counters
    MODIFY COLUMN k VARCHAR(255) NOT NULL
    COMMENT '计数器键：{scope}:epoch / {scope}:subject:{id}:version / !global:epoch';

SET @has_idx := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'rbac_user_grants' AND index_name = 'idx_subject_expires');
SET @ddl := IF(@has_idx > 0, 'DO 0',
    'ALTER TABLE rbac_user_grants ADD KEY idx_subject_expires (subject_id, revoked_at, expires_at)');
PREPARE mig_stmt FROM @ddl;
EXECUTE mig_stmt;
DEALLOCATE PREPARE mig_stmt;
