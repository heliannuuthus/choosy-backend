package models

import (
	"time"
)

// RefreshToken 刷新令牌
type RefreshToken struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	OpenID    string    `gorm:"not null;index;column:openid;size:64" json:"-"` // 关联 users.openid
	Token     string    `gorm:"not null;uniqueIndex;size:128" json:"token"`
	ExpiresAt time.Time `gorm:"not null;column:expires_at" json:"expires_at"`
	CreatedAt time.Time `gorm:"not null;column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at" json:"updated_at"`
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}
