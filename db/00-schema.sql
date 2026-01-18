-- Choosy 数据库 Schema
-- MySQL 语法
-- 无外键约束，在应用层处理关联关系
-- 所有表主键统一为 _id (INT AUTO_INCREMENT)

-- ==================== 用户相关 ====================

-- 用户表
CREATE TABLE IF NOT EXISTS t_user (
    _id             INT AUTO_INCREMENT PRIMARY KEY,
    openid          VARCHAR(64) NOT NULL COMMENT '系统生成的唯一标识（对外 ID）',
    nickname        VARCHAR(64) NOT NULL COMMENT '昵称',
    avatar          VARCHAR(512) NOT NULL COMMENT '头像 URL',
    phone           VARCHAR(64) COMMENT '手机号哈希（SHA256，用于查询）',
    encrypted_phone VARCHAR(128) COMMENT '手机号密文（AES-GCM，IV在前，用于展示）',
    gender          TINYINT NOT NULL DEFAULT 0 COMMENT '性别 0未知 1男 2女',
    status          TINYINT NOT NULL DEFAULT 0 COMMENT '账号状态 0正常 1禁用',
    last_login_at   DATETIME COMMENT '最后登录时间',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_t_user_openid (openid),
    INDEX idx_t_user_phone (phone)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 用户身份表（多端绑定）
CREATE TABLE IF NOT EXISTS t_user_identity (
    _id         INT AUTO_INCREMENT PRIMARY KEY,
    openid      VARCHAR(64) NOT NULL COMMENT '关联 t_user.openid',
    idp         VARCHAR(64) NOT NULL COMMENT '身份提供方，格式 provider:namespace（如 wechat:mp / tt:mp / wechat:unionid）',
    t_openid    VARCHAR(128) NOT NULL COMMENT '第三方原始标识',
    raw_data    TEXT COMMENT '原始授权数据 JSON（可选）',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_idp_t_openid (idp, t_openid) COMMENT '同 idp 下 t_openid 唯一',
    INDEX idx_t_user_identity_openid (openid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 刷新令牌表
CREATE TABLE IF NOT EXISTS t_refresh_token (
    _id         INT AUTO_INCREMENT PRIMARY KEY,
    openid      VARCHAR(64) NOT NULL COMMENT '关联 t_user.openid',
    token       VARCHAR(128) NOT NULL COMMENT '令牌值',
    expires_at  DATETIME NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_t_refresh_token_token (token),
    INDEX idx_t_refresh_token_openid (openid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 用户偏好表（存储用户选择的偏好选项）
CREATE TABLE IF NOT EXISTS t_user_preference (
    _id         INT AUTO_INCREMENT PRIMARY KEY,
    openid      VARCHAR(64) NOT NULL COMMENT '关联 t_user.openid',
    tag_value   VARCHAR(50) NOT NULL COMMENT '关联 t_tag.value',
    tag_type    VARCHAR(20) NOT NULL COMMENT '关联 t_tag.type（冗余字段，优化查询）',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_openid_tag (openid, tag_value, tag_type) COMMENT '防止重复选择',
    INDEX idx_t_user_preference_openid (openid),
    INDEX idx_t_user_preference_tag_type (tag_type),
    INDEX idx_t_user_preference_openid_type (openid, tag_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ==================== 菜谱相关 ====================

-- 菜谱主表
CREATE TABLE IF NOT EXISTS t_recipe (
    _id                 INT AUTO_INCREMENT PRIMARY KEY,
    recipe_id           VARCHAR(32) NOT NULL COMMENT 'Base62 随机 ID（对外 ID，22位）',
    name                VARCHAR(128) NOT NULL COMMENT '菜名',
    description         TEXT COMMENT '描述',
    images              TEXT COMMENT '图片列表 (JSON 数组)，第一张为主图',
    category            VARCHAR(32) COMMENT '分类',
    difficulty          INT DEFAULT 1 COMMENT '难度 1-5',
    servings            INT DEFAULT 1 COMMENT '份数',
    prep_time_minutes   INT COMMENT '准备时间(分钟)',
    cook_time_minutes   INT COMMENT '烹饪时间(分钟)',
    total_time_minutes  INT COMMENT '总时间(分钟)',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_t_recipe_recipe_id (recipe_id),
    UNIQUE KEY uk_t_recipe_name (name),
    INDEX idx_t_recipe_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 食材表
CREATE TABLE IF NOT EXISTS t_ingredient (
    _id             INT AUTO_INCREMENT PRIMARY KEY,
    recipe_id       VARCHAR(32) NOT NULL COMMENT '关联 t_recipe.recipe_id',
    name            VARCHAR(64) NOT NULL COMMENT '食材名称',
    category        VARCHAR(32) COMMENT '关联 t_ingredient_category.key',
    quantity        DOUBLE COMMENT '数量',
    unit            VARCHAR(64) NOT NULL COMMENT '单位',
    notes           TEXT COMMENT '备注',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_t_ingredient_recipe_id (recipe_id),
    INDEX idx_t_ingredient_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 步骤表
CREATE TABLE IF NOT EXISTS t_step (
    _id             INT AUTO_INCREMENT PRIMARY KEY,
    recipe_id       VARCHAR(32) NOT NULL COMMENT '关联 t_recipe.recipe_id',
    step            INT NOT NULL COMMENT '步骤序号',
    description     TEXT NOT NULL COMMENT '步骤描述',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_t_step_recipe_id (recipe_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 小贴士表
CREATE TABLE IF NOT EXISTS t_additional_note (
    _id             INT AUTO_INCREMENT PRIMARY KEY,
    recipe_id       VARCHAR(32) NOT NULL COMMENT '关联 t_recipe.recipe_id',
    note            TEXT NOT NULL COMMENT '小贴士内容',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_t_additional_note_recipe_id (recipe_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ==================== 标签相关 ====================

-- 标签表（独立存储，不关联菜谱）
-- 存储所有标签定义，包括菜谱标签（cuisine/flavor/scene）和用户偏好选项（taboo/allergy）
CREATE TABLE IF NOT EXISTS t_tag (
    _id         INT AUTO_INCREMENT PRIMARY KEY,
    value       VARCHAR(50) NOT NULL COMMENT '标签值 (如 sichuan, spicy, no_pork)',
    label       VARCHAR(50) NOT NULL COMMENT '显示名称 (如 川菜, 香辣, 不吃猪肉)',
    type        VARCHAR(20) NOT NULL COMMENT '类型: cuisine/flavor/scene/taboo/allergy',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_type_value (type, value) COMMENT '确保同一类型下 value 唯一',
    INDEX idx_t_tag_value (value),
    INDEX idx_t_tag_type (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 菜谱标签关联表（存储菜谱和标签的多对多关系）
CREATE TABLE IF NOT EXISTS t_recipe_tag (
    _id         INT AUTO_INCREMENT PRIMARY KEY,
    recipe_id   VARCHAR(32) NOT NULL COMMENT '关联 t_recipe.recipe_id',
    tag_value   VARCHAR(50) NOT NULL COMMENT '关联 t_tag.value',
    tag_type    VARCHAR(20) NOT NULL COMMENT '关联 t_tag.type（冗余字段，优化查询）',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_recipe_tag (recipe_id, tag_value, tag_type) COMMENT '防止重复关联',
    INDEX idx_t_recipe_tag_recipe_id (recipe_id),
    INDEX idx_t_recipe_tag_tag_value (tag_value),
    INDEX idx_t_recipe_tag_tag_type (tag_type),
    INDEX idx_t_recipe_tag_recipe_type (recipe_id, tag_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ==================== 食材分类相关 ====================

-- 食材分类表
CREATE TABLE IF NOT EXISTS t_ingredient_category (
    _id         INT AUTO_INCREMENT PRIMARY KEY,
    `key`       VARCHAR(32) NOT NULL COMMENT '分类标识符 (meat/seafood/vegetable...)',
    label       VARCHAR(32) NOT NULL COMMENT '中文名称',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_t_ingredient_category_key (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ==================== 收藏相关 ====================

-- 收藏表
CREATE TABLE IF NOT EXISTS t_favorite (
    _id         INT AUTO_INCREMENT PRIMARY KEY,
    openid      VARCHAR(64) NOT NULL COMMENT '关联 t_user.openid',
    recipe_id   VARCHAR(32) NOT NULL COMMENT '关联 t_recipe.recipe_id',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_t_favorite_openid (openid),
    INDEX idx_t_favorite_recipe_id (recipe_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ==================== 浏览历史相关 ====================

-- 浏览历史表
CREATE TABLE IF NOT EXISTS t_view_history (
    _id         INT AUTO_INCREMENT PRIMARY KEY,
    openid      VARCHAR(64) NOT NULL COMMENT '关联 t_user.openid',
    recipe_id   VARCHAR(64) NOT NULL COMMENT '关联 t_recipe.recipe_id',
    viewed_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_t_view_history_user (openid),
    INDEX idx_t_view_history_recipe_id (recipe_id),
    INDEX idx_t_view_history_user_viewed (openid, viewed_at),
    INDEX idx_t_view_history_user_recipe (openid, recipe_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
