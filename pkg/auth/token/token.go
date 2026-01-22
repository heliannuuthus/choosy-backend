package token

import (
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// AccessToken 访问令牌
type AccessToken struct {
	// 标准 JWT claims
	JTI       string
	Issuer    string
	Subject   string // 用户 ID
	Audience  []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	NotBefore time.Time

	// 自定义 claims
	ClientID string // 客户端 ID（从 aud 提取）
	Scope    string // 权限范围

	// 用户信息（M2M 时为空）
	Email    string
	Phone    string
	Picture  string
	Nickname string
}

// NewAccessToken 从 jwt.Token 构造 AccessToken
func NewAccessToken(token jwt.Token) *AccessToken {
	jti, _ := token.JwtID()
	issuer, _ := token.Issuer()
	audience, _ := token.Audience()
	issuedAt, _ := token.IssuedAt()
	expiration, _ := token.Expiration()
	notBefore, _ := token.NotBefore()
	subject, _ := token.Subject()

	at := &AccessToken{
		JTI:       jti,
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		IssuedAt:  issuedAt,
		ExpiresAt: expiration,
		NotBefore: notBefore,
	}

	if len(audience) > 0 {
		at.ClientID = audience[0]
	}

	var scope string
	if err := token.Get("scope", &scope); err == nil {
		at.Scope = scope
	}

	return at
}

// WithUserInfo 设置用户信息
func (a *AccessToken) WithUserInfo(sub, nickname, picture, email, phone string) *AccessToken {
	a.Subject = sub
	a.Nickname = nickname
	a.Picture = picture
	a.Email = email
	a.Phone = phone
	return a
}

// IsM2M 判断是否是 M2M 场景（无用户信息）
func (a *AccessToken) IsM2M() bool {
	return a.Email == "" && a.Phone == "" && a.Nickname == ""
}

// IsExpired 判断是否已过期
func (a *AccessToken) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// HasScope 判断是否包含指定 scope
func (a *AccessToken) HasScope(scope string) bool {
	if a.Scope == "" {
		return false
	}
	for _, s := range strings.Fields(a.Scope) {
		if s == scope {
			return true
		}
	}
	return false
}
