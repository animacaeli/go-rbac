-- 0001_init_core: go-rbac 五张核心表（设计文档 §5.2 冻结稿，逐字对应）
-- 基准：MySQL 8.0+ / InnoDB / utf8mb4_0900_ai_ci

CREATE TABLE IF NOT EXISTS rbac_roles (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code        VARCHAR(64)  NOT NULL COMMENT '角色代码，授权域内唯一；启用租户后唯一键变为(tenant_id, code)',
    name        VARCHAR(128) NOT NULL COMMENT '展示名',
    description VARCHAR(255) NOT NULL DEFAULT '',
    is_builtin  TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '1=内置受保护角色(如超管载体)，禁止删除/禁用',
    status      TINYINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '1=启用 0=禁用',
    created_at  DATETIME(3) NOT NULL,
    updated_at  DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS rbac_permissions (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code        VARCHAR(128) NOT NULL COMMENT '权限码，全局唯一且稳定，格式 模块:操作',
    name        VARCHAR(128) NOT NULL,
    module      VARCHAR(64)  NOT NULL COMMENT '分组展示用',
    description VARCHAR(255) NOT NULL DEFAULT '',
    status      TINYINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '1=启用 0=禁用 2=已废弃(代码不再注册)',
    created_at  DATETIME(3) NOT NULL,
    updated_at  DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_code (code),
    KEY idx_module (module)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 纯关联表：撤销即物理删除，历史由 Audit 模块负责
CREATE TABLE IF NOT EXISTS rbac_user_roles (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    subject_id VARCHAR(128) NOT NULL COMMENT '外部用户标识，非本库外键',
    role_id    BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_subject_role (subject_id, role_id),
    KEY idx_role (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS rbac_role_permissions (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    role_id       BIGINT UNSIGNED NOT NULL,
    permission_id BIGINT UNSIGNED NOT NULL,
    created_at    DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_role_permission (role_id, permission_id),
    KEY idx_permission (permission_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 唯一保留完整生命周期的表：撤销/过期记录不删，服务审计
CREATE TABLE IF NOT EXISTS rbac_user_grants (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    subject_id    VARCHAR(128) NOT NULL,
    permission_id BIGINT UNSIGNED NOT NULL,
    expires_at    DATETIME(3) NULL COMMENT 'NULL=永久；缓存TTL不得超过最近到期时间',
    reason        VARCHAR(255) NOT NULL DEFAULT '',
    created_by    VARCHAR(128) NOT NULL COMMENT '操作人 subject_id',
    created_at    DATETIME(3) NOT NULL,
    revoked_at    DATETIME(3) NULL,
    revoked_by    VARCHAR(128) NULL,
    active_flag   TINYINT GENERATED ALWAYS AS (IF(revoked_at IS NULL, 1, NULL)) STORED
                  COMMENT '撤销行为NULL，不参与唯一约束；兜底防重复活跃授权',
    PRIMARY KEY (id),
    UNIQUE KEY uk_subject_permission_active (subject_id, permission_id, active_flag),
    KEY idx_permission (permission_id),
    KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
