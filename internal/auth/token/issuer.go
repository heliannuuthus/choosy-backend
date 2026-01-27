package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	pkgtoken "github.com/heliannuuthus/helios/pkg/token"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// KeyStore 密钥存储
type KeyStore struct {
	signKey    []byte // 签名密钥（原始字节）
	encryptKey []byte // 加密密钥（原始字节）
}

// SetSignKey 设置签名密钥
func (s *KeyStore) SetSignKey(key []byte) {
	s.signKey = key
}

// SetEncryptKey 设置加密密钥
func (s *KeyStore) SetEncryptKey(key []byte) {
	s.encryptKey = key
}

// GetSignKey 获取签名密钥（解析为 JWK）
func (s *KeyStore) GetSignKey() (jwk.Key, error) {
	if s.signKey == nil {
		return nil, errors.New("sign key not set")
	}
	return jwk.ParseKey(s.signKey)
}

// GetEncryptKey 获取加密密钥（解析为 JWK）
func (s *KeyStore) GetEncryptKey() (jwk.Key, error) {
	if s.encryptKey == nil {
		return nil, errors.New("encrypt key not set")
	}
	return jwk.Import(s.encryptKey)
}

// Issuer Token 签发器
type Issuer struct {
	issuerName string
	store      *KeyStore
}

// NewIssuer 创建 Token 签发器
func NewIssuer(issuerName string) *Issuer {
	return &Issuer{
		issuerName: issuerName,
		store:      &KeyStore{},
	}
}

// GetIssuerName 返回签发者名称
func (i *Issuer) GetIssuerName() string {
	return i.issuerName
}

// SetSignKey 设置签名密钥
func (i *Issuer) SetSignKey(key []byte) {
	i.store.SetSignKey(key)
}

// SetEncryptKey 设置加密密钥
func (i *Issuer) SetEncryptKey(key []byte) {
	i.store.SetEncryptKey(key)
}

// Issue 签发 token
func (i *Issuer) Issue(accessToken AccessToken) (string, error) {
	// 获取签名密钥
	signKey, err := i.store.GetSignKey()
	if err != nil {
		return "", fmt.Errorf("get sign key: %w", err)
	}

	// 构建 JWT Token
	token, err := accessToken.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 如果是 UserAccessToken，需要加密用户信息到 sub
	if uat, ok := accessToken.(*UserAccessToken); ok && uat.GetUser() != nil {
		encryptKey, err := i.store.GetEncryptKey()
		if err != nil {
			return "", fmt.Errorf("get encrypt key: %w", err)
		}
		encryptedSub, err := i.encryptClaims(uat.GetUser(), encryptKey)
		if err != nil {
			return "", fmt.Errorf("encrypt user claims: %w", err)
		}
		_ = token.Set(jwt.SubjectKey, encryptedSub)
	}

	// 签名
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), signKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// IssueUserToken 签发用户访问令牌
func (i *Issuer) IssueUserToken(
	clientID, audience, scope string,
	ttl time.Duration,
	user *pkgtoken.Claims,
) (string, error) {
	uat := NewUserAccessToken(i.issuerName, clientID, audience, scope, ttl, user)
	return i.Issue(uat)
}

// IssueServiceToken 签发服务访问令牌
func (i *Issuer) IssueServiceToken(
	clientID, audience, scope string,
	ttl time.Duration,
) (string, error) {
	sat := NewServiceAccessToken(i.issuerName, clientID, audience, scope, ttl)
	return i.Issue(sat)
}

// encryptClaims 加密用户信息
func (i *Issuer) encryptClaims(claims *pkgtoken.Claims, encryptKey jwk.Key) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	if encryptKey == nil {
		return string(data), nil
	}

	encrypted, err := jwe.Encrypt(data,
		jwe.WithKey(jwa.DIRECT(), encryptKey),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", fmt.Errorf("jwe encrypt: %w", err)
	}

	return string(encrypted), nil
}

// decryptClaims 解密用户信息
func (i *Issuer) decryptClaims(encryptedSub string, decryptKey jwk.Key) (*pkgtoken.Claims, error) {
	var data []byte

	if decryptKey == nil {
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

	var claims pkgtoken.Claims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// VerifyAccessToken 验证 Access Token，返回身份信息
func (i *Issuer) VerifyAccessToken(tokenString string) (*Identity, error) {
	signKey, err := i.store.GetSignKey()
	if err != nil {
		return nil, fmt.Errorf("get sign key: %w", err)
	}

	// 验证签名
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), signKey),
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
	encryptKey, err := i.store.GetEncryptKey()
	if err != nil {
		return nil, fmt.Errorf("get encrypt key: %w", err)
	}

	claims, err := i.decryptClaims(encryptedSub, encryptKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt sub: %w", err)
	}

	// 获取 scope
	var scope string
	_ = token.Get("scope", &scope)

	return &Identity{
		OpenID:   claims.OpenID,
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

// VerifyAccessTokenGlobal 兼容旧接口（全局函数）
// Deprecated: 使用 Issuer.VerifyAccessToken 替代
func VerifyAccessTokenGlobal(tokenString string) (*Identity, error) {
	// 此函数已废弃，需要使用带密钥的 Issuer
	return nil, errors.New("VerifyAccessTokenGlobal is deprecated, use Issuer.VerifyAccessToken instead")
}
