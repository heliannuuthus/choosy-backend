package token

import (
	"errors"
	"strings"
	"time"
)

// 验证错误
var (
	ErrUnsupportedAudience = errors.New("unsupported audience")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrMissingClaims       = errors.New("missing required claims")
	ErrNoKeysInJWKS        = errors.New("no keys in JWKS")
)

// Identity Token 解析后的身份信息
type Identity struct {
	UserID   string    `json:"sub"`
	ClientID string    `json:"cli,omitempty"` // 应用 ID
	Audience string    `json:"aud,omitempty"` // 服务 ID
	Scope    string    `json:"scope"`
	Nickname string    `json:"nickname,omitempty"`
	Picture  string    `json:"picture,omitempty"`
	Email    string    `json:"email,omitempty"`
	Phone    string    `json:"phone,omitempty"`
	Issuer   string    `json:"iss,omitempty"` // 签发者
	IssuedAt time.Time `json:"iat,omitempty"` // 签发时间
	ExpireAt time.Time `json:"exp,omitempty"` // 过期时间
}

// GetOpenID 兼容旧接口
func (i *Identity) GetOpenID() string {
	return i.UserID
}

// OpenID 兼容旧接口
func (i *Identity) OpenID() string {
	return i.UserID
}

// HasScope 检查是否包含某个 scope
func (i *Identity) HasScope(scope string) bool {
	scopes := strings.Fields(i.Scope)
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// SubjectClaims sub 字段解密后的内容
type SubjectClaims struct {
	OpenID   string `json:"openid"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
}
