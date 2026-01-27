package token

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Issuer Token 签发器
// 集成 encryptor + signer，负责 token 的签发和验证
type Issuer struct {
	issuerName string  // issuer 字符串
	signingKey jwk.Key // 默认签名密钥（用于旧接口兼容）
	encryptKey jwk.Key // 默认加密密钥（用于旧接口兼容）
}

// NewIssuer 创建 Token 签发器
func NewIssuer() (*Issuer, error) {
	i := &Issuer{
		issuerName: config.GetString("auth.issuer"),
	}

	// 加载默认签名密钥（兼容旧接口）
	signKeyB64 := config.GetString("kms.token.sign-key")
	if signKeyB64 != "" {
		keyBytes, err := base64.RawURLEncoding.DecodeString(signKeyB64)
		if err != nil {
			return nil, fmt.Errorf("decode signing key: %w", err)
		}
		key, err := jwk.ParseKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse signing key: %w", err)
		}
		i.signingKey = key
	}

	// 加载默认加密密钥（兼容旧接口）
	encKeyB64 := config.GetString("kms.token.enc-key")
	if encKeyB64 != "" {
		keyBytes, err := base64.RawURLEncoding.DecodeString(encKeyB64)
		if err != nil {
			return nil, fmt.Errorf("decode encrypt key: %w", err)
		}
		key, err := jwk.ParseKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse encrypt key: %w", err)
		}
		i.encryptKey = key
	}

	return i, nil
}

// Issue 签发 token（新版本）
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
	_ = token.Set(jwt.IssuerKey, i.issuerName)
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

// IssueWithDefaults 使用默认密钥签发 token（旧版兼容）
// Deprecated: 使用 Issue 替代
func (i *Issuer) IssueWithDefaults(claims *SubjectClaims, clientID string, scope string, ttl time.Duration) (string, error) {
	now := time.Now()

	// 加密 sub（用户信息）
	encryptedSub, err := i.encryptSubjectClaims(claims, i.encryptKey)
	if err != nil {
		return "", fmt.Errorf("encrypt sub: %w", err)
	}

	// 创建 JWT
	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, i.issuerName)
	_ = token.Set(jwt.SubjectKey, encryptedSub)
	_ = token.Set(jwt.AudienceKey, clientID)
	_ = token.Set(jwt.IssuedAtKey, now.Unix())
	_ = token.Set(jwt.ExpirationKey, now.Add(ttl).Unix())
	_ = token.Set(jwt.NotBeforeKey, now.Unix())

	// JTI
	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	_ = token.Set(jwt.JwtIDKey, hex.EncodeToString(jtiBytes))

	// scope
	_ = token.Set("scope", scope)

	// 签名
	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), i.signingKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signedToken), nil
}

// VerifyAccessToken 验证 Access Token，返回完整身份信息（旧版兼容）
func (i *Issuer) VerifyAccessToken(tokenString string) (*Identity, error) {
	// 验证签名
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), i.signingKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 获取加密的 sub
	encryptedSub, ok := token.Subject()
	if !ok {
		return nil, errors.New("missing sub")
	}

	// 解密 sub
	claims, err := i.decryptSubjectClaims(encryptedSub, i.encryptKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt sub: %w", err)
	}

	// 获取 scope
	var scope string
	_ = token.Get("scope", &scope)

	return &Identity{
		UserID:   claims.OpenID,
		Scope:    scope,
		Nickname: claims.Nickname,
		Picture:  claims.Picture,
		Email:    claims.Email,
		Phone:    claims.Phone,
	}, nil
}

// ParseAccessTokenUnverified 解析 Token 但不验证（用于获取 claims）
func (i *Issuer) ParseAccessTokenUnverified(tokenString string) (aud string, iss string, exp int64, iat int64, scope string, err error) {
	token, parseErr := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if parseErr != nil {
		err = parseErr
		return
	}

	if audVal, ok := token.Audience(); ok && len(audVal) > 0 {
		aud = audVal[0]
	}
	if issVal, ok := token.Issuer(); ok {
		iss = issVal
	}
	if expVal, ok := token.Expiration(); ok {
		exp = expVal.Unix()
	}
	if iatVal, ok := token.IssuedAt(); ok {
		iat = iatVal.Unix()
	}
	_ = token.Get("scope", &scope)
	return
}

// VerifyServiceJWT 验证 Service JWT（用于 introspect）
func (i *Issuer) VerifyServiceJWT(tokenString string, serviceKey []byte) (serviceID string, jti string, err error) {
	// 使用 HMAC 验证
	key, err := jwk.Import(serviceKey)
	if err != nil {
		return "", "", fmt.Errorf("import service key: %w", err)
	}

	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.HS256(), key),
		jwt.WithValidate(true),
	)
	if err != nil {
		return "", "", fmt.Errorf("verify service jwt: %w", err)
	}

	sub, ok := token.Subject()
	if !ok {
		return "", "", errors.New("missing sub in service jwt")
	}

	jtiVal, _ := token.JwtID()

	return sub, jtiVal, nil
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

// decryptSubjectClaims 解密用户信息
func (i *Issuer) decryptSubjectClaims(encryptedSub string, decryptKey jwk.Key) (*SubjectClaims, error) {
	var data []byte

	if decryptKey == nil {
		// 没有解密密钥则直接解析 JSON
		data = []byte(encryptedSub)
	} else {
		decrypted, err := jwe.Decrypt([]byte(encryptedSub),
			jwe.WithKey(jwa.DIRECT(), decryptKey),
		)
		if err != nil {
			return nil, err
		}
		data = decrypted
	}

	var claims SubjectClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// VerifyAccessTokenGlobal 兼容旧接口（全局函数）
func VerifyAccessTokenGlobal(tokenString string) (*Identity, error) {
	issuer, err := NewIssuer()
	if err != nil {
		return nil, err
	}
	return issuer.VerifyAccessToken(tokenString)
}
