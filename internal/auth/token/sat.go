package token

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ServiceAccessToken 服务访问令牌
// 用于 M2M（机器对机器）通信，不包含用户信息
type ServiceAccessToken struct {
	issuer    string        // 签发者
	clientID  string        // cli - 应用 ID
	audience  string        // aud - 服务 ID
	scope     string        // 授权范围
	ttl       time.Duration // 有效期
	notBefore time.Time     // 生效时间
}

// NewServiceAccessToken 创建 ServiceAccessToken
func NewServiceAccessToken(issuer, clientID, audience, scope string, ttl time.Duration) *ServiceAccessToken {
	return &ServiceAccessToken{
		issuer:    issuer,
		clientID:  clientID,
		audience:  audience,
		scope:     scope,
		ttl:       ttl,
		notBefore: time.Now(),
	}
}

// Build 构建 JWT Token（不包含签名）
// ServiceAccessToken 没有 sub 字段（无用户信息）
func (s *ServiceAccessToken) Build() (jwt.Token, error) {
	now := time.Now()

	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, s.issuer)
	_ = token.Set(jwt.AudienceKey, s.audience) // aud = service_id
	_ = token.Set("cli", s.clientID)           // cli = client_id
	_ = token.Set(jwt.IssuedAtKey, now.Unix())
	_ = token.Set(jwt.ExpirationKey, now.Add(s.ttl).Unix())
	_ = token.Set(jwt.NotBeforeKey, s.notBefore.Unix())

	// JTI
	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	_ = token.Set(jwt.JwtIDKey, hex.EncodeToString(jtiBytes))

	// scope
	_ = token.Set("scope", s.scope)

	// 无 sub 字段

	return token, nil
}

// GetIssuer 返回签发者
func (s *ServiceAccessToken) GetIssuer() string {
	return s.issuer
}

// GetClientID 返回应用 ID
func (s *ServiceAccessToken) GetClientID() string {
	return s.clientID
}

// GetAudience 返回服务 ID
func (s *ServiceAccessToken) GetAudience() string {
	return s.audience
}

// ExpiresIn 返回有效期
func (s *ServiceAccessToken) ExpiresIn() time.Duration {
	return s.ttl
}

// GetNotBefore 返回生效时间
func (s *ServiceAccessToken) GetNotBefore() time.Time {
	return s.notBefore
}

// GetScope 返回授权范围
func (s *ServiceAccessToken) GetScope() string {
	return s.scope
}
