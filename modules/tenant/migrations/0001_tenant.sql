-- 0001_tenant: 多租户迁移契约（§2.9 / §5.5 冻结稿）
-- 契约：ADD COLUMN tenant_id（默认空串 = default 域）→ 存量回填 → 重建全部受影响唯一键：
--   rbac_roles.uk_code                        → (tenant_id, code)
--   rbac_user_roles.uk_subject_role           → (tenant_id, subject_id, role_id)
--   rbac_user_grants.uk_subject_permission_active → (tenant_id, subject_id, permission_id, active_flag)
-- MySQL ADD COLUMN ... NOT NULL DEFAULT '' 对存量行自动回填默认值；显式 UPDATE
-- 为契约的可读性保留（幂等）。DDL 隐式提交：逐语句执行，可重入（§5.7）。

ALTER TABLE rbac_roles
    ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT '' COMMENT '租户标识，空串=default 域（平台域）' AFTER id;

UPDATE rbac_roles SET tenant_id = '' WHERE tenant_id IS NULL;

ALTER TABLE rbac_roles
    DROP KEY uk_code,
    ADD UNIQUE KEY uk_tenant_code (tenant_id, code);

ALTER TABLE rbac_user_roles
    ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT '' AFTER id;

UPDATE rbac_user_roles SET tenant_id = '' WHERE tenant_id IS NULL;

ALTER TABLE rbac_user_roles
    DROP KEY uk_subject_role,
    ADD UNIQUE KEY uk_tenant_subject_role (tenant_id, subject_id, role_id);

ALTER TABLE rbac_user_grants
    ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT '' AFTER id;

UPDATE rbac_user_grants SET tenant_id = '' WHERE tenant_id IS NULL;

ALTER TABLE rbac_user_grants
    DROP KEY uk_subject_permission_active,
    ADD UNIQUE KEY uk_tenant_subject_permission_active (tenant_id, subject_id, permission_id, active_flag);
