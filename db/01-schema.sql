-- Choosy 数据库 Schema
-- SQLite 语法
-- 无外键约束，在应用层处理关联关系
-- 所有表主键统一为 _id (INTEGER AUTOINCREMENT)

-- ==================== 用户相关 ====================

-- 用户表
CREATE TABLE IF NOT EXISTS t_user (
    _id             INTEGER PRIMARY KEY AUTOINCREMENT,
    openid          VARCHAR(64) NOT NULL UNIQUE,    -- 系统生成的唯一标识（对外 ID）
    nickname        VARCHAR(64) NOT NULL,           -- 昵称
    avatar          VARCHAR(512) NOT NULL,          -- 头像 URL
    phone           VARCHAR(64),                    -- 手机号哈希（SHA256，用于查询）
    encrypted_phone VARCHAR(128),                   -- 手机号密文（AES-GCM，IV在前，用于展示）
    gender          TINYINT NOT NULL DEFAULT 0,     -- 性别 0未知 1男 2女
    status          TINYINT NOT NULL DEFAULT 0,     -- 账号状态 0正常 1禁用
    last_login_at   DATETIME,                       -- 最后登录时间
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_t_user_openid ON t_user(openid);
CREATE INDEX IF NOT EXISTS idx_t_user_phone ON t_user(phone);  -- 改为普通索引，支持多端数据互通（同一手机号可绑定多个账号）

-- 用户身份表（多端绑定）
CREATE TABLE IF NOT EXISTS t_user_identity (
    _id         INTEGER PRIMARY KEY AUTOINCREMENT,
    openid      VARCHAR(64) NOT NULL,           -- 关联 t_user.openid
    idp         VARCHAR(64) NOT NULL,           -- 身份提供方，格式 provider:namespace（如 wechat:mp / tt:mp / wechat:unionid）
    t_openid    VARCHAR(128) NOT NULL,          -- 第三方原始标识
    raw_data    TEXT,                           -- 原始授权数据 JSON（可选）
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(idp, t_openid)                       -- 同 idp 下 t_openid 唯一
);
CREATE INDEX IF NOT EXISTS idx_t_user_identity_openid ON t_user_identity(openid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_t_user_identity_idp_t_openid ON t_user_identity(idp, t_openid);

-- 刷新令牌表
CREATE TABLE IF NOT EXISTS t_refresh_token (
    _id         INTEGER PRIMARY KEY AUTOINCREMENT,
    openid      VARCHAR(64) NOT NULL,           -- 关联 t_user.openid
    token       VARCHAR(128) NOT NULL UNIQUE,   -- 令牌值
    expires_at  DATETIME NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_t_refresh_token_openid ON t_refresh_token(openid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_t_refresh_token_token ON t_refresh_token(token);

-- ==================== 菜谱相关 ====================

-- 菜谱主表
CREATE TABLE IF NOT EXISTS t_recipe (
    _id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id           VARCHAR(32) NOT NULL UNIQUE,   -- Base62 随机 ID（对外 ID，22位）
    name                VARCHAR(128) NOT NULL UNIQUE,  -- 菜名
    description         TEXT,                          -- 描述
    images              TEXT DEFAULT '[]',             -- 图片列表 (JSON 数组)，第一张为主图
    category            VARCHAR(32),                   -- 分类
    difficulty          INTEGER DEFAULT 1,             -- 难度 1-5
    servings            INTEGER DEFAULT 1,             -- 份数
    prep_time_minutes   INTEGER,                       -- 准备时间(分钟)
    cook_time_minutes   INTEGER,                       -- 烹饪时间(分钟)
    total_time_minutes  INTEGER,                       -- 总时间(分钟)
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_t_recipe_recipe_id ON t_recipe(recipe_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_t_recipe_name ON t_recipe(name);
CREATE INDEX IF NOT EXISTS idx_t_recipe_category ON t_recipe(category);

-- 食材表
CREATE TABLE IF NOT EXISTS t_ingredient (
    _id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id       VARCHAR(32) NOT NULL,       -- 关联 t_recipe.recipe_id
    name            VARCHAR(64) NOT NULL,       -- 食材名称
    category        VARCHAR(32),                -- 关联 t_ingredient_category.key
    quantity        REAL,                       -- 数量
    unit            VARCHAR(16),                -- 单位
    text_quantity   VARCHAR(32) NOT NULL,       -- 文本描述的数量
    notes           TEXT,                       -- 备注
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_t_ingredient_recipe_id ON t_ingredient(recipe_id);
CREATE INDEX IF NOT EXISTS idx_t_ingredient_category ON t_ingredient(category);

-- 步骤表
CREATE TABLE IF NOT EXISTS t_step (
    _id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id       VARCHAR(32) NOT NULL,       -- 关联 t_recipe.recipe_id
    step            INTEGER NOT NULL,           -- 步骤序号
    description     TEXT NOT NULL,              -- 步骤描述
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_t_step_recipe_id ON t_step(recipe_id);

-- 小贴士表
CREATE TABLE IF NOT EXISTS t_additional_note (
    _id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id       VARCHAR(32) NOT NULL,       -- 关联 t_recipe.recipe_id
    note            TEXT NOT NULL,              -- 小贴士内容
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_t_additional_note_recipe_id ON t_additional_note(recipe_id);

-- ==================== 标签相关 ====================

-- 标签表（直接关联菜谱）
CREATE TABLE IF NOT EXISTS t_tag (
    _id         INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id   VARCHAR(16) NOT NULL,           -- 关联 t_recipe.recipe_id
    value       VARCHAR(50) NOT NULL,           -- 标签值 (如 sichuan, spicy)
    label       VARCHAR(50) NOT NULL,           -- 显示名称 (如 川菜, 香辣)
    type        VARCHAR(20) NOT NULL,           -- 类型: cuisine/flavor/scene
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_t_tag_recipe_id ON t_tag(recipe_id);
CREATE INDEX IF NOT EXISTS idx_t_tag_value ON t_tag(value);
CREATE INDEX IF NOT EXISTS idx_t_tag_type ON t_tag(type);

-- ==================== 食材分类相关 ====================

-- 食材分类表
CREATE TABLE IF NOT EXISTS t_ingredient_category (
    _id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key         VARCHAR(32) NOT NULL UNIQUE,     -- 分类标识符 (meat/seafood/vegetable...)
    label       VARCHAR(32) NOT NULL,            -- 中文名称
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_t_ingredient_category_key ON t_ingredient_category(key);

-- ==================== 收藏相关 ====================

-- 收藏表
CREATE TABLE IF NOT EXISTS t_favorite (
    _id         INTEGER PRIMARY KEY AUTOINCREMENT,
    openid      VARCHAR(64) NOT NULL,           -- 关联 t_user.openid
    recipe_id   VARCHAR(16) NOT NULL,           -- 关联 t_recipe.recipe_id
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_t_favorite_openid ON t_favorite(openid);
CREATE INDEX IF NOT EXISTS idx_t_favorite_recipe_id ON t_favorite(recipe_id);

-- ==================== 浏览历史相关 ====================

-- 浏览历史表
CREATE TABLE IF NOT EXISTS t_view_history (
    _id         INTEGER PRIMARY KEY AUTOINCREMENT,
    openid      VARCHAR(64) NOT NULL,           -- 关联 t_user.openid
    recipe_id   VARCHAR(64) NOT NULL,           -- 关联 t_recipe.recipe_id
    viewed_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_t_view_history_user ON t_view_history(openid);
CREATE INDEX IF NOT EXISTS idx_t_view_history_recipe_id ON t_view_history(recipe_id);
-- 联合索引：优化按用户查询并按时间排序（SQLite 不支持索引中的 DESC，查询时使用 ORDER BY DESC）
CREATE INDEX IF NOT EXISTS idx_t_view_history_user_viewed ON t_view_history(openid, viewed_at);
-- 联合索引：优化按用户和菜谱查询
CREATE INDEX IF NOT EXISTS idx_t_view_history_user_recipe ON t_view_history(openid, recipe_id);
