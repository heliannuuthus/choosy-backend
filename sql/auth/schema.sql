-- Auth 数据库 Schema（认证数据）
-- MySQL 语法
-- 注意：session、authorization_code、refresh_token 都存储在 Redis 中
-- 注意：IDP 配置从配置文件读取，不需要建表

-- ==================== 数据库初始化 ====================
-- 创建 auth 数据库（如果不存在）
CREATE DATABASE IF NOT EXISTS `auth` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 授予用户权限（MYSQL_USER 环境变量创建的用户，默认用户名是 helios）
-- 注意：如果修改了 MYSQL_USER，需要同步修改这里的用户名
GRANT ALL PRIVILEGES ON `auth`.* TO 'helios'@'%';
FLUSH PRIVILEGES;

-- 使用 auth 数据库
USE `auth`;

-- ==================== 域相关 ====================

-- 域表（密钥在配置，表只存元信息）
CREATE TABLE IF NOT EXISTS t_domain (
    _id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id VARCHAR(32) NOT NULL COMMENT '域标识：ciam/piam',
    name VARCHAR(128) NOT NULL COMMENT '域名称',
    description TEXT COMMENT '描述',
    status TINYINT DEFAULT 0 COMMENT '状态：0=active, 1=disabled',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_domain_id (domain_id),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='域';

-- ==================== 服务相关 ====================

-- 服务表
CREATE TABLE IF NOT EXISTS t_service (
    _id INT AUTO_INCREMENT PRIMARY KEY,
    service_id VARCHAR(32) NOT NULL COMMENT '服务标识：zwei/atlas/order',
    domain_id VARCHAR(32) NOT NULL COMMENT '所属域（关联 t_domain.domain_id）',
    name VARCHAR(128) NOT NULL COMMENT '服务名称',
    description TEXT COMMENT '描述',
    encrypted_key TEXT NOT NULL COMMENT '服务 AES 密钥（用域加密密钥加密，AES-GCM）',
    access_token_expires_in INT DEFAULT 7200 COMMENT 'Access Token 有效期（秒）',
    refresh_token_expires_in INT DEFAULT 604800 COMMENT 'Refresh Token 有效期（秒）',
    status TINYINT DEFAULT 0 COMMENT '状态：0=active, 1=disabled',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_service_id (service_id),
    INDEX idx_domain_id (domain_id),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='业务服务';

-- ==================== 应用相关 ====================

-- 应用表（OAuth2 客户端）
CREATE TABLE IF NOT EXISTS t_application (
    _id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id VARCHAR(32) NOT NULL COMMENT '所属域（关联 t_domain.domain_id）',
    app_id VARCHAR(64) NOT NULL COMMENT '应用唯一标识',
    name VARCHAR(128) NOT NULL COMMENT '应用名称',
    redirect_uris TEXT DEFAULT NULL COMMENT '重定向 URI 列表（JSON 数组），NULL 表示不需要重定向',
    encrypted_key TEXT DEFAULT NULL COMMENT '应用密钥（用域加密密钥加密，AES-GCM，AAD=app_id），NULL 表示无密钥',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_app_id (app_id) COMMENT '应用 ID 全局唯一',
    UNIQUE KEY uk_domain_app_id (domain_id, app_id) COMMENT '同一域下应用 ID 唯一',
    INDEX idx_domain_id (domain_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='OAuth2 应用';

-- 应用可访问的服务和关系
CREATE TABLE IF NOT EXISTS t_application_service_relation (
    _id INT AUTO_INCREMENT PRIMARY KEY,
    app_id VARCHAR(64) NOT NULL COMMENT '应用 ID（关联 t_application.app_id）',
    service_id VARCHAR(32) NOT NULL COMMENT '服务 ID（关联 t_service.service_id）',
    relation VARCHAR(32) NOT NULL COMMENT '允许的关系，* 表示全部',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_app_service_relation (app_id, service_id, relation),
    INDEX idx_app_id (app_id),
    INDEX idx_service_id (service_id),
    INDEX idx_app_service (app_id, service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='应用可访问的服务和关系';

-- ==================== 用户相关 ====================

-- ==================== 用户相关 ====================

-- 用户表
CREATE TABLE IF NOT EXISTS t_user (
    _id INT AUTO_INCREMENT PRIMARY KEY COMMENT '主键',
    domain_id VARCHAR(32) NOT NULL COMMENT '所属域（关联 t_domain.domain_id）',
    openid VARCHAR(64) NOT NULL COMMENT '用户唯一标识',
    nickname VARCHAR(128) COMMENT '昵称',
    picture VARCHAR(512) COMMENT '头像 URL',
    email VARCHAR(256) COMMENT '邮箱（明文存储）',
    email_verified TINYINT(1) DEFAULT 0 COMMENT '邮箱是否已验证',
    phone VARCHAR(64) COMMENT '手机号哈希（SHA256）',
    phone_cipher VARCHAR(256) COMMENT '手机号密文（AES-GCM）',
    status TINYINT DEFAULT 0 COMMENT '状态：0=active, 1=disabled',
    last_login_at DATETIME COMMENT '最后登录时间',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_openid (openid) COMMENT '用户 OpenID 全局唯一',
    UNIQUE KEY uk_email (email) COMMENT '邮箱唯一（允许 NULL）',
    UNIQUE KEY uk_phone (phone) COMMENT '手机号唯一（允许 NULL）',
    INDEX idx_domain_id (domain_id),
    INDEX idx_status (status),
    INDEX idx_last_login_at (last_login_at),
    INDEX idx_domain_status (domain_id, status) COMMENT '按域和状态查询'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户';

-- 用户身份表（IDP 绑定）
-- 注意：用户在没有互相绑定之前允许具有多个身份
CREATE TABLE IF NOT EXISTS t_user_identity (
    _id INT AUTO_INCREMENT PRIMARY KEY COMMENT '主键',
    openid VARCHAR(64) NOT NULL COMMENT '用户标识',
    idp VARCHAR(64) NOT NULL COMMENT 'IDP 标识',
    t_openid VARCHAR(256) NOT NULL COMMENT '第三方原始标识（IDP 返回的用户标识）',
    raw_data TEXT COMMENT 'IDP 返回的原始数据（JSON）',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_idp_t_openid (idp, t_openid) COMMENT '同 IDP 下 t_openid 唯一',
    UNIQUE KEY uk_openid_idp (openid, idp) COMMENT '同一用户在同一 IDP 下唯一身份',
    INDEX idx_idp (idp),
    CONSTRAINT fk_identity_user FOREIGN KEY (openid) REFERENCES t_user(openid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户身份';

-- ==================== ReBAC 权限相关 ====================

-- 关系表（ReBAC 核心）
CREATE TABLE IF NOT EXISTS t_relationship (
    _id INT AUTO_INCREMENT PRIMARY KEY,
    service_id VARCHAR(32) NOT NULL COMMENT '所属服务（关联 t_service.service_id）',
    subject_type VARCHAR(32) NOT NULL COMMENT '主体类型：user/group/application',
    subject_id VARCHAR(64) NOT NULL COMMENT '主体 ID',
    relation VARCHAR(32) NOT NULL COMMENT '关系：owner/editor/viewer/member/admin',
    object_type VARCHAR(32) NOT NULL COMMENT '资源类型：recipe/user/category',
    object_id VARCHAR(128) NOT NULL COMMENT '资源 ID，* 表示全部',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME DEFAULT NULL COMMENT '过期时间',
    UNIQUE KEY uk_relationship (service_id, subject_type, subject_id, relation, object_type, object_id),
    INDEX idx_service_id (service_id),
    INDEX idx_subject (subject_type, subject_id),
    INDEX idx_object (service_id, object_type, object_id),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='权限关系';

-- 用户组
CREATE TABLE IF NOT EXISTS t_group (
    _id INT AUTO_INCREMENT PRIMARY KEY,
    group_id VARCHAR(64) NOT NULL COMMENT '组标识',
    name VARCHAR(128) NOT NULL COMMENT '组名称',
    description TEXT COMMENT '描述',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_group_id (group_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户组';
