package token

import (
	"errors"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// 验证错误
var (
	ErrUnsupportedAudience = errors.New("unsupported audience")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrMissingClaims       = errors.New("missing required claims")
	ErrNoKeysInJWKS        = errors.New("no keys in JWKS")
)

// AccessToken 定义 token 构建接口
// 各种类型的 token（ClientAccessToken, ServiceAccessToken, UserAccessToken）都实现此接口
type AccessToken interface {
	// Build 构建 JWT Token（不包含签名）
	Build() (jwt.Token, error)

	// 标准 JWT 字段 getter
	GetIssuer() string
	GetClientID() string
	GetAudience() string
	ExpiresIn() time.Duration
	GetNotBefore() time.Time
}

// Claims 统一的身份信息结构
// 用于：1) 加密到 sub 中  2) Interpreter 解释后返回
type Claims struct {
	// JWT 标准字段
	Issuer   string    `json:"iss,omitempty"`
	Audience string    `json:"aud,omitempty"`
	IssuedAt time.Time `json:"iat,omitempty"`
	ExpireAt time.Time `json:"exp,omitempty"`

	// 自定义字段
	ClientID string `json:"cli,omitempty"` // 应用 ID
	Scope    string `json:"scope,omitempty"`

	// 用户信息（根据 scope 决定是否填充）
	OpenID   string `json:"openid,omitempty"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

// GetOpenID 返回 OpenID
func (c *Claims) GetOpenID() string {
	return c.OpenID
}

// HasScope 检查是否包含某个 scope
func (c *Claims) HasScope(scope string) bool {
	scopes := strings.Fields(c.Scope)
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
