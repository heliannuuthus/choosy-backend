package models

import (
	"time"
)

// User 用户信息
type User struct {
	ID             uint       `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	OpenID         string     `gorm:"not null;uniqueIndex;column:openid;size:64" json:"openid"` // 系统生成的唯一标识，作为对外 ID
	Nickname       string     `gorm:"not null;column:nickname;size:64" json:"nickname"`         // 昵称
	Avatar         string     `gorm:"not null;column:avatar;size:512" json:"avatar"`            // 头像 URL
	Phone          *string    `gorm:"column:phone;size:64;index" json:"-"`                      // 手机号哈希（SHA256，用于查询，支持多端数据互通）
	EncryptedPhone *string    `gorm:"column:encrypted_phone;size:128" json:"-"`                 // 手机号密文（AES-GCM，用于展示）
	Gender         int8       `gorm:"not null;column:gender;default:0" json:"gender"`           // 性别 0未知 1男 2女
	Status         int8       `gorm:"not null;column:status;default:0" json:"status"`           // 账号状态 0正常 1禁用
	LastLoginAt    *time.Time `gorm:"column:last_login_at" json:"last_login_at,omitempty"`      // 最后登录时间
	CreatedAt      time.Time  `gorm:"not null;column:created_at" json:"created_at"`
	UpdatedAt      time.Time  `gorm:"not null;column:updated_at" json:"updated_at"`
}

func (User) TableName() string {
	return "t_user"
}

// UserIdentity 用户身份表（多端绑定）
type UserIdentity struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	OpenID    string    `gorm:"not null;index;column:openid;size:64" json:"-"` // 关联 t_user.openid
	IDP       string    `gorm:"not null;column:idp;size:64" json:"idp"`        // 身份提供方，格式 provider:namespace
	TOpenID   string    `gorm:"not null;column:t_openid;size:128" json:"-"`    // 第三方原始标识
	RawData   *string   `gorm:"column:raw_data;type:text" json:"-"`            // 原始授权数据 JSON
	CreatedAt time.Time `gorm:"not null;column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at" json:"updated_at"`
}

func (UserIdentity) TableName() string {
	return "t_user_identity"
}
