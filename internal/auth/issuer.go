package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Issuer token 签发器（仅 Auth 模块使用）
type Issuer struct {
	issuer string
}

// NewIssuer 创建签发器
func NewIssuer(issuer string) *Issuer {
	return &Issuer{
		issuer: issuer,
	}
}

// Issue 签发 token
// 使用服务密钥加密用户信息，使用域密钥签名
// - claims: 用户信息
// - clientID: 应用 ID（存储在 cli 字段）
// - audience: 服务 ID（存储在 aud 字段）
// - serviceEncryptKey: 服务加密密钥（用于加密 sub）
// - signKey: 域签名密钥（用于签名 JWT）
// - scope: 授权范围
// - ttl: token 有效期
func (i *Issuer) Issue(
	claims *SubjectClaims,
	clientID string,
	audience string,
	serviceEncryptKey jwk.Key,
	signKey jwk.Key,
	scope string,
	ttl time.Duration,
) (string, error) {
	now := time.Now()

	// 使用服务密钥加密 sub（用户信息）
	encryptedSub, err := i.encryptSubjectClaims(claims, serviceEncryptKey)
	if err != nil {
		return "", fmt.Errorf("encrypt sub: %w", err)
	}

	// 创建 JWT
	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, i.issuer)
	_ = token.Set(jwt.SubjectKey, encryptedSub)
	_ = token.Set(jwt.AudienceKey, audience) // aud = service_id
	_ = token.Set("cli", clientID)           // cli = client_id
	_ = token.Set(jwt.IssuedAtKey, now.Unix())
	_ = token.Set(jwt.ExpirationKey, now.Add(ttl).Unix())
	_ = token.Set(jwt.NotBeforeKey, now.Unix())

	// JTI
	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	_ = token.Set(jwt.JwtIDKey, hex.EncodeToString(jtiBytes))

	// scope
	_ = token.Set("scope", scope)

	// 使用域签名密钥签名
	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), signKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signedToken), nil
}

// encryptSubjectClaims 使用指定密钥加密用户信息
func (i *Issuer) encryptSubjectClaims(claims *SubjectClaims, encryptKey jwk.Key) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	if encryptKey == nil {
		// 没有加密密钥则返回 JSON
		return string(data), nil
	}

	encrypted, err := jwe.Encrypt(data,
		jwe.WithKey(jwa.DIRECT(), encryptKey),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", err
	}

	return string(encrypted), nil
}
