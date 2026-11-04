-- 0001_data_scopes: 数据范围表（§2.8 / §5.6，datascope 模块贡献）
-- 功能权限回答"能否执行操作"，数据权限回答"能操作哪些数据"。
-- 四种枚举范围（§2.8 冻结决策）：1=SELF 2=DEPARTMENT 3=DEPARTMENT_AND_CHILDREN 4=ALL；
-- CUSTOM 延后至独立设计（见 docs/phase3-evaluation.md）。
CREATE TABLE IF NOT EXISTS rbac_role_data_scopes (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    role_id    BIGINT UNSIGNED NOT NULL COMMENT '角色（角色归属由角色行本身决定）',
    resource   VARCHAR(64)  NOT NULL COMMENT '资源/模块标识，如 order',
    scope      TINYINT UNSIGNED NOT NULL COMMENT '1=SELF 2=DEPARTMENT 3=DEPARTMENT_AND_CHILDREN 4=ALL',
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_role_resource (role_id, resource)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
