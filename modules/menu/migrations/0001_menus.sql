-- 0001_menus: 菜单模块表（§2.7 / §5.6，menu 模块贡献）
-- 菜单是前端导航资源，不等同于权限资源；与权限可选关联（rbac_menu_permissions）。
CREATE TABLE IF NOT EXISTS rbac_menus (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    parent_id   BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '0=根节点',
    code        VARCHAR(64)  NOT NULL COMMENT '菜单代码，全局唯一稳定标识',
    name        VARCHAR(128) NOT NULL COMMENT '展示名',
    type        TINYINT UNSIGNED NOT NULL COMMENT '1=目录 2=页面 3=外部链接',
    path        VARCHAR(255) NOT NULL DEFAULT '' COMMENT '路由地址或外链 URL',
    component   VARCHAR(255) NOT NULL DEFAULT '' COMMENT '前端组件标识（页面类型）',
    icon        VARCHAR(64)  NOT NULL DEFAULT '' COMMENT '图标标识',
    sort        INT          NOT NULL DEFAULT 0 COMMENT '同级排序，小者在前',
    status      TINYINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '1=启用 0=禁用',
    created_at  DATETIME(3) NOT NULL,
    updated_at  DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_code (code),
    KEY idx_parent (parent_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 菜单与权限的可选关联：无关联 = 对所有已认证用户可见；
-- 有关联 = 持有任一关联权限（启用状态）即可见（OR 语义，§2.7）。
CREATE TABLE IF NOT EXISTS rbac_menu_permissions (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    menu_id       BIGINT UNSIGNED NOT NULL,
    permission_id BIGINT UNSIGNED NOT NULL,
    created_at    DATETIME(3) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_menu_permission (menu_id, permission_id),
    KEY idx_permission (permission_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
