-- Choosy 数据库 Schema
-- SQLite 语法
-- 无外键约束，在应用层处理关联关系
-- 所有表主键统一为 _id (INTEGER AUTOINCREMENT)

-- ==================== 用户相关 ====================

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    _id         INTEGER PRIMARY KEY AUTOINCREMENT,
    openid      VARCHAR(64) NOT NULL UNIQUE,    -- 系统生成的唯一标识（对外 ID）
    t_openid    VARCHAR(64) NOT NULL UNIQUE,    -- 第三方平台原始 openid
    nickname    VARCHAR(64) NOT NULL,           -- 昵称
    avatar      VARCHAR(512) NOT NULL,          -- 头像 URL
    created_at  DATETIME NOT NULL,
    updated_at  DATETIME NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_openid ON users(openid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_t_openid ON users(t_openid);

-- 刷新令牌表
CREATE TABLE IF NOT EXISTS refresh_tokens (
    _id         INTEGER PRIMARY KEY AUTOINCREMENT,
    openid      VARCHAR(64) NOT NULL,           -- 关联 users.openid
    token       VARCHAR(128) NOT NULL UNIQUE,   -- 令牌值
    expires_at  DATETIME NOT NULL,
    created_at  DATETIME NOT NULL,
    updated_at  DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_openid ON refresh_tokens(openid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);

-- ==================== 菜谱相关 ====================

-- 菜谱主表
CREATE TABLE IF NOT EXISTS recipes (
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
    total_time_minutes  INTEGER                        -- 总时间(分钟)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_recipes_recipe_id ON recipes(recipe_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_recipes_name ON recipes(name);
CREATE INDEX IF NOT EXISTS idx_recipes_category ON recipes(category);

-- 食材表
CREATE TABLE IF NOT EXISTS ingredients (
    _id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id       VARCHAR(32) NOT NULL,       -- 关联 recipes.recipe_id
    name            VARCHAR(64) NOT NULL,       -- 食材名称
    quantity        REAL,                       -- 数量
    unit            VARCHAR(16),                -- 单位
    text_quantity   VARCHAR(32) NOT NULL,       -- 文本描述的数量
    notes           TEXT                        -- 备注
);
CREATE INDEX IF NOT EXISTS idx_ingredients_recipe_id ON ingredients(recipe_id);

-- 步骤表
CREATE TABLE IF NOT EXISTS steps (
    _id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id       VARCHAR(32) NOT NULL,       -- 关联 recipes.recipe_id
    step            INTEGER NOT NULL,           -- 步骤序号
    description     TEXT NOT NULL               -- 步骤描述
);
CREATE INDEX IF NOT EXISTS idx_steps_recipe_id ON steps(recipe_id);

-- 小贴士表
CREATE TABLE IF NOT EXISTS additional_notes (
    _id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id       VARCHAR(32) NOT NULL,       -- 关联 recipes.recipe_id
    note            TEXT NOT NULL               -- 小贴士内容
);
CREATE INDEX IF NOT EXISTS idx_additional_notes_recipe_id ON additional_notes(recipe_id);

-- ==================== 标签相关 ====================

-- 标签表（直接关联菜谱）
CREATE TABLE IF NOT EXISTS tags (
    _id         INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id   VARCHAR(16) NOT NULL,           -- 关联 recipes.recipe_id
    value       VARCHAR(50) NOT NULL,           -- 标签值 (如 sichuan, spicy)
    label       VARCHAR(50) NOT NULL,           -- 显示名称 (如 川菜, 香辣)
    type        VARCHAR(20) NOT NULL            -- 类型: cuisine/flavor/scene
);
CREATE INDEX IF NOT EXISTS idx_tags_recipe_id ON tags(recipe_id);
CREATE INDEX IF NOT EXISTS idx_tags_value ON tags(value);
CREATE INDEX IF NOT EXISTS idx_tags_type ON tags(type);

-- ==================== 收藏相关 ====================

-- 收藏表
CREATE TABLE IF NOT EXISTS favorites (
    _id         INTEGER PRIMARY KEY AUTOINCREMENT,
    openid      VARCHAR(64) NOT NULL,           -- 用户 openid
    recipe_id   VARCHAR(16) NOT NULL,           -- 关联 recipes.recipe_id
    created_at  DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_favorites_openid ON favorites(openid);
CREATE INDEX IF NOT EXISTS idx_favorites_recipe_id ON favorites(recipe_id);
