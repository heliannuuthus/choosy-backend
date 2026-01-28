package token

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/heliannuuthus/helios/pkg/auth/token"
)

// UserAccessToken 用户访问令牌
// 包含用户身份信息，sub 字段为加密的用户信息（JWE）
type UserAccessToken struct {
	issuer    string        // 签发者
	clientID  string        // cli - 应用 ID
	audience  string        // aud - 服务 ID
	scope     string        // 授权范围
	ttl       time.Duration // 有效期
	notBefore time.Time     // 生效时间
	user      *token.Claims // 用户信息（根据 scope 填充）
}

// NewUserAccessToken 创建 UserAccessToken
func NewUserAccessToken(issuer, clientID, audience, scope string, ttl time.Duration, user *token.Claims) *UserAccessToken {
	return &UserAccessToken{
		issuer:    issuer,
		clientID:  clientID,
		audience:  audience,
		scope:     scope,
		ttl:       ttl,
		notBefore: time.Now(),
		user:      user,
	}
}

// Build 构建 JWT Token（不包含签名）
// 注意：sub 字段需要在 Issuer 中使用 Encryptor 加密后设置
func (u *UserAccessToken) Build() (jwt.Token, error) {
	now := time.Now()

	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, u.issuer)
	_ = token.Set(jwt.AudienceKey, u.audience) // aud = service_id
	_ = token.Set("cli", u.clientID)           // cli = client_id
	_ = token.Set(jwt.IssuedAtKey, now.Unix())
	_ = token.Set(jwt.ExpirationKey, now.Add(u.ttl).Unix())
	_ = token.Set(jwt.NotBeforeKey, u.notBefore.Unix())

	// JTI
	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	_ = token.Set(jwt.JwtIDKey, hex.EncodeToString(jtiBytes))

	// scope
	_ = token.Set("scope", u.scope)

	// 注意：sub 字段由 Issuer 加密后设置

	return token, nil
}

// GetIssuer 返回签发者
func (u *UserAccessToken) GetIssuer() string {
	return u.issuer
}

// GetClientID 返回应用 ID
func (u *UserAccessToken) GetClientID() string {
	return u.clientID
}

// GetAudience 返回服务 ID
func (u *UserAccessToken) GetAudience() string {
	return u.audience
}

// ExpiresIn 返回有效期
func (u *UserAccessToken) ExpiresIn() time.Duration {
	return u.ttl
}

// GetNotBefore 返回生效时间
func (u *UserAccessToken) GetNotBefore() time.Time {
	return u.notBefore
}

// GetUser 返回用户信息
func (u *UserAccessToken) GetUser() *token.Claims {
	return u.user
}

// GetScope 返回授权范围
func (u *UserAccessToken) GetScope() string {
	return u.scope
}

// UserClaimsFromScope 根据 scope 构建用户 Claims
// scope 决定哪些用户信息会被包含在 token 中
func UserClaimsFromScope(openID, nickname, picture, email, phone, scope string) *token.Claims {
	claims := &token.Claims{
		OpenID: openID,
	}

	// 根据 scope 填充字段
	scopeSet := parseScopeSet(scope)

	if scopeSet["profile"] {
		claims.Nickname = nickname
		claims.Picture = picture
	}

	if scopeSet["email"] {
		claims.Email = email
	}

	if scopeSet["phone"] {
		claims.Phone = phone
	}

	return claims
}

// parseScopeSet 解析 scope 字符串为集合
func parseScopeSet(scope string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range splitScope(scope) {
		set[s] = true
	}
	return set
}

// splitScope 分割 scope 字符串
func splitScope(scope string) []string {
	var result []string
	start := 0
	for i := 0; i < len(scope); i++ {
		if scope[i] == ' ' {
			if i > start {
				result = append(result, scope[start:i])
			}
			start = i + 1
		}
	}
	if start < len(scope) {
		result = append(result, scope[start:])
	}
	return result
}
