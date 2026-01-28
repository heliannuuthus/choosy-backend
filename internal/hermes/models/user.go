package models

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// User 用户
type User struct {
	ID            uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	Domain        string    `json:"domain" gorm:"column:domain;size:32;not null;index"`
	OpenID        string    `json:"id" gorm:"column:openid;size:64;not null;uniqueIndex"`
	Name          string    `json:"name" gorm:"column:name;size:128"`
	Picture       string    `json:"picture" gorm:"column:picture;size:512"`
	Email         *string   `json:"email" gorm:"column:email;size:256;index"`
	EmailVerified bool      `json:"email_verified" gorm:"column:email_verified;default:false"`
	Phone         *string   `json:"-" gorm:"column:phone;size:64;index"`   // 手机号哈希（用于查询）
	PhoneCipher   *string   `json:"-" gorm:"column:phone_cipher;size:256"` // 手机号密文
	Status        int8      `json:"status" gorm:"column:status;default:0"` // 0=active, 1=disabled
	LastLoginAt   time.Time `json:"last_login_at" gorm:"column:last_login_at"`
	CreatedAt     time.Time `json:"created_at" gorm:"column:created_at"`
	UpdatedAt     time.Time `json:"updated_at" gorm:"column:updated_at"`
}

func (User) TableName() string {
	return "t_user"
}

// IsActive 用户是否活跃
func (u *User) IsActive() bool {
	return u.Status == 0
}

// UserIdentity 用户身份（IDP 绑定）
type UserIdentity struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	OpenID    string    `gorm:"column:openid;size:64;not null;index"`
	IDP       string    `gorm:"column:idp;size:64;not null;uniqueIndex:uk_idp_t_openid,priority:1"`
	TOpenID   string    `gorm:"column:t_openid;size:256;not null;uniqueIndex:uk_idp_t_openid,priority:2"` // 第三方原始标识
	UnionID   string    `gorm:"column:union_id;size:256"`
	RawData   string    `gorm:"column:raw_data;type:text"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (UserIdentity) TableName() string {
	return "t_user_identity"
}

// UserWithDecrypted 解密后的用户信息（业务层使用）
type UserWithDecrypted struct {
	User
	Phone string `json:"phone,omitempty"` // 解密后的手机号
}

// SafeString 脱敏输出（用于日志）
func (u *UserWithDecrypted) SafeString() string {
	return fmt.Sprintf("User{OpenID:%s, Domain:%s, Name:%s, Email:%s, Phone:%s}",
		u.OpenID,
		u.Domain,
		u.Name,
		maskEmail(u.Email),
		maskPhone(u.Phone),
	)
}

// String 实现 Stringer 接口，打印时自动脱敏
func (u *UserWithDecrypted) String() string {
	return u.SafeString()
}

// GenerateOpenID 生成用户 OpenID
func GenerateOpenID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("generate openid failed: %v", err))
	}
	return hex.EncodeToString(bytes)
}

// maskEmail 邮箱脱敏：a**@example.com
func maskEmail(email *string) string {
	if email == nil || *email == "" {
		return ""
	}
	e := *email
	parts := strings.Split(e, "@")
	if len(parts) != 2 {
		return e
	}
	local := parts[0]
	if len(local) <= 1 {
		return local + "**@" + parts[1]
	}
	return string(local[0]) + "**@" + parts[1]
}

// maskPhone 手机号脱敏：138****1234
func maskPhone(phone string) string {
	if phone == "" {
		return ""
	}
	if len(phone) <= 7 {
		return phone
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}

// FindOrCreateUserRequest 查找或创建用户请求
type FindOrCreateUserRequest struct {
	Domain     string // 用户域
	IDP        string // 身份提供方
	ProviderID string // IDP 侧用户标识
	UnionID    string // 联合 ID（可选）
	RawData    string // 原始数据
}
