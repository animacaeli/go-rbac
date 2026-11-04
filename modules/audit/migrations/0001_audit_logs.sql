-- 0001_audit: 授权变更审计表（§5.6，audit 模块贡献）
-- 审计模块是关联关系历史的唯一归属（§5.3）：rbac_user_roles / rbac_role_permissions
-- 物理删除后，历史由本表追溯。
CREATE TABLE IF NOT EXISTS rbac_audit_logs (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    event_type  VARCHAR(64)  NOT NULL COMMENT '事件类型（core.EventType）',
    operator_id VARCHAR(128) NOT NULL COMMENT '操作人 subject_id',
    tenant_id   VARCHAR(64)  NOT NULL DEFAULT '',
    target      VARCHAR(255) NOT NULL DEFAULT '' COMMENT '目标对象（角色 code / subject_id 等）',
    detail      TEXT         NULL COMMENT '变更内容摘要（JSON）',
    created_at  DATETIME(3)  NOT NULL,
    PRIMARY KEY (id),
    KEY idx_operator (operator_id),
    KEY idx_event (event_type),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
