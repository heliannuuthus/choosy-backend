package models

import (
	"time"
)

// User 用户信息
type User struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	OpenID    string    `gorm:"not null;uniqueIndex;column:openid;size:64" json:"openid"` // 系统生成的唯一标识，作为对外 ID
	TOpenID   string    `gorm:"not null;uniqueIndex;column:t_openid;size:64" json:"-"`    // 第三方平台原始 openid
	Nickname  string    `gorm:"not null;column:nickname;size:64" json:"nickname"`         // 昵称
	Avatar    string    `gorm:"not null;column:avatar;size:512" json:"avatar"`            // 头像 URL
	CreatedAt time.Time `gorm:"not null;column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at" json:"updated_at"`
}

func (User) TableName() string {
	return "users"
}
