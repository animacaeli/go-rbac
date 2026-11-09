-- 0003_counter_key_width: 计数器键列宽与授权到期索引。
--
-- 1) rbac_counters.k 原为 VARCHAR(191)，但主体版本键最长可达
--    "{tenant(64)}:subject:{subject(128)}:version" ≈ 209 字符，长租户 + 长主体
--    在严格模式下会触发 1406（Data too long），使整个授权变更事务回滚。
--    列同时改为 utf8mb4_0900_bin（身份键按字节比较，见迁移 0004）：迁移在
--    "schema_migrations 丢失、数据仍在"的场景下会重跑，若此处回退到 ai_ci，
--    仅大小写不同的既有键会撞主键，故显式保持二进制语义。
--    已 >= 255 时跳过（幂等）。
-- 2) 授权到期查询（subject_id + revoked_at + expires_at）缺少覆盖索引；
--    用 information_schema 判断 + 动态 DDL 保证可重入。

SET @k_len := (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_counters' AND column_name = 'k');
SET @ddl := IF(COALESCE(@k_len, 0) >= 255, 'DO 0',
    'ALTER TABLE rbac_counters MODIFY COLUMN k VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL');
PREPARE mig_stmt FROM @ddl;
EXECUTE mig_stmt;
DEALLOCATE PREPARE mig_stmt;

SET @has_idx := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'rbac_user_grants' AND index_name = 'idx_subject_expires');
SET @ddl := IF(@has_idx > 0, 'DO 0',
    'ALTER TABLE rbac_user_grants ADD KEY idx_subject_expires (subject_id, revoked_at, expires_at)');
PREPARE mig_stmt FROM @ddl;
EXECUTE mig_stmt;
DEALLOCATE PREPARE mig_stmt;
