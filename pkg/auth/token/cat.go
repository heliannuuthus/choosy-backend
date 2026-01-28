package token

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ClientAccessToken 用于 Client-Credentials 流程
// 应用使用自己的密钥签发 JWS，向 Auth Service 请求 ServiceAccessToken
type ClientAccessToken struct {
	issuer    string        // 签发者
	clientID  string        // 应用 ID
	audience  string        // 目标服务（通常是 auth service）
	ttl       time.Duration // 有效期
	notBefore time.Time     // 生效时间
}

// NewClientAccessToken 创建 ClientAccessToken
func NewClientAccessToken(issuer, clientID, audience string, ttl time.Duration) *ClientAccessToken {
	return &ClientAccessToken{
		issuer:    issuer,
		clientID:  clientID,
		audience:  audience,
		ttl:       ttl,
		notBefore: time.Now(),
	}
}

// Build 构建 JWT Token（不包含签名）
func (c *ClientAccessToken) Build() (jwt.Token, error) {
	now := time.Now()

	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, c.issuer)
	_ = token.Set(jwt.SubjectKey, c.clientID) // sub = client_id
	_ = token.Set(jwt.AudienceKey, c.audience)
	_ = token.Set(jwt.IssuedAtKey, now.Unix())
	_ = token.Set(jwt.ExpirationKey, now.Add(c.ttl).Unix())
	_ = token.Set(jwt.NotBeforeKey, c.notBefore.Unix())

	// JTI
	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	_ = token.Set(jwt.JwtIDKey, hex.EncodeToString(jtiBytes))

	return token, nil
}

// GetIssuer 返回签发者
func (c *ClientAccessToken) GetIssuer() string {
	return c.issuer
}

// GetClientID 返回应用 ID
func (c *ClientAccessToken) GetClientID() string {
	return c.clientID
}

// GetAudience 返回目标服务
func (c *ClientAccessToken) GetAudience() string {
	return c.audience
}

// ExpiresIn 返回有效期
func (c *ClientAccessToken) ExpiresIn() time.Duration {
	return c.ttl
}

// GetNotBefore 返回生效时间
func (c *ClientAccessToken) GetNotBefore() time.Time {
	return c.notBefore
}
