-- 0001_tenant: 多租户迁移契约（§2.9 / §5.5 冻结稿）
-- 契约：ADD COLUMN tenant_id（默认空串 = default 域）→ 存量回填 → 重建全部受影响唯一键：
--   rbac_roles.uk_code                        → (tenant_id, code)
--   rbac_user_roles.uk_subject_role           → (tenant_id, subject_id, role_id)
--   rbac_user_grants.uk_subject_permission_active → (tenant_id, subject_id, permission_id, active_flag)
--
-- 可重入性（§5.7）：MySQL DDL 隐式提交且 8.0 不支持 ADD COLUMN IF NOT EXISTS，
-- 因此用 information_schema 判断 + 动态 DDL（PREPARE/EXECUTE）实现"对象已存在
-- 则跳过"。执行器（migrations.Apply）保证同一迁移的语句跑在同一条连接上，
-- 会话变量 @has_* / @ddl 才能跨语句生效——部分失败后重跑不会卡在 1060。

-- ---- rbac_roles ----
SET @has_col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_roles' AND column_name = 'tenant_id');
SET @ddl := IF(@has_col > 0, 'DO 0',
    'ALTER TABLE rbac_roles ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT '''' AFTER id');
PREPARE mig_stmt FROM @ddl;
EXECUTE mig_stmt;
DEALLOCATE PREPARE mig_stmt;

UPDATE rbac_roles SET tenant_id = '' WHERE tenant_id IS NULL;

SET @has_new := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'rbac_roles' AND index_name = 'uk_tenant_code');
SET @has_old := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'rbac_roles' AND index_name = 'uk_code');
SET @ddl := IF(@has_new > 0,
    IF(@has_old > 0, 'ALTER TABLE rbac_roles DROP KEY uk_code', 'DO 0'),
    IF(@has_old > 0,
        'ALTER TABLE rbac_roles DROP KEY uk_code, ADD UNIQUE KEY uk_tenant_code (tenant_id, code)',
        'ALTER TABLE rbac_roles ADD UNIQUE KEY uk_tenant_code (tenant_id, code)'));
PREPARE mig_stmt FROM @ddl;
EXECUTE mig_stmt;
DEALLOCATE PREPARE mig_stmt;

-- ---- rbac_user_roles ----
SET @has_col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_user_roles' AND column_name = 'tenant_id');
SET @ddl := IF(@has_col > 0, 'DO 0',
    'ALTER TABLE rbac_user_roles ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT '''' AFTER id');
PREPARE mig_stmt FROM @ddl;
EXECUTE mig_stmt;
DEALLOCATE PREPARE mig_stmt;

UPDATE rbac_user_roles SET tenant_id = '' WHERE tenant_id IS NULL;

SET @has_new := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'rbac_user_roles' AND index_name = 'uk_tenant_subject_role');
SET @has_old := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'rbac_user_roles' AND index_name = 'uk_subject_role');
SET @ddl := IF(@has_new > 0,
    IF(@has_old > 0, 'ALTER TABLE rbac_user_roles DROP KEY uk_subject_role', 'DO 0'),
    IF(@has_old > 0,
        'ALTER TABLE rbac_user_roles DROP KEY uk_subject_role, ADD UNIQUE KEY uk_tenant_subject_role (tenant_id, subject_id, role_id)',
        'ALTER TABLE rbac_user_roles ADD UNIQUE KEY uk_tenant_subject_role (tenant_id, subject_id, role_id)'));
PREPARE mig_stmt FROM @ddl;
EXECUTE mig_stmt;
DEALLOCATE PREPARE mig_stmt;

-- ---- rbac_user_grants ----
SET @has_col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_user_grants' AND column_name = 'tenant_id');
SET @ddl := IF(@has_col > 0, 'DO 0',
    'ALTER TABLE rbac_user_grants ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT '''' AFTER id');
PREPARE mig_stmt FROM @ddl;
EXECUTE mig_stmt;
DEALLOCATE PREPARE mig_stmt;

UPDATE rbac_user_grants SET tenant_id = '' WHERE tenant_id IS NULL;

SET @has_new := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'rbac_user_grants' AND index_name = 'uk_tenant_subject_permission_active');
SET @has_old := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'rbac_user_grants' AND index_name = 'uk_subject_permission_active');
SET @ddl := IF(@has_new > 0,
    IF(@has_old > 0, 'ALTER TABLE rbac_user_grants DROP KEY uk_subject_permission_active', 'DO 0'),
    IF(@has_old > 0,
        'ALTER TABLE rbac_user_grants DROP KEY uk_subject_permission_active, ADD UNIQUE KEY uk_tenant_subject_permission_active (tenant_id, subject_id, permission_id, active_flag)',
        'ALTER TABLE rbac_user_grants ADD UNIQUE KEY uk_tenant_subject_permission_active (tenant_id, subject_id, permission_id, active_flag)'));
PREPARE mig_stmt FROM @ddl;
EXECUTE mig_stmt;
DEALLOCATE PREPARE mig_stmt;
