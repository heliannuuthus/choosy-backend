package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/internal/config"
	pkgtoken "github.com/heliannuuthus/helios/pkg/token"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Issuer Token 签发器
type Issuer struct {
	issuerName string    // issuer 字符串
	encryptor  Encryptor // 加密器
	signer     Signer    // 签名器

	// 默认密钥（用于旧接口兼容）
	signingKey jwk.Key
	encryptKey jwk.Key
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
		i.signer = NewEdDSASigner(key)
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
		i.encryptor = NewJWEEncryptor(key)
	}

	return i, nil
}

// NewIssuerWithCrypto 创建带加密器和签名器的 Token 签发器
func NewIssuerWithCrypto(issuerName string, encryptor Encryptor, signer Signer) *Issuer {
	return &Issuer{
		issuerName: issuerName,
		encryptor:  encryptor,
		signer:     signer,
	}
}

// GetIssuerName 返回签发者名称
func (i *Issuer) GetIssuerName() string {
	return i.issuerName
}

// SetEncryptor 设置加密器
func (i *Issuer) SetEncryptor(encryptor Encryptor) {
	i.encryptor = encryptor
}

// SetSigner 设置签名器
func (i *Issuer) SetSigner(signer Signer) {
	i.signer = signer
}

// WithEncryptor 返回设置了加密器的新 Issuer（链式调用）
func (i *Issuer) WithEncryptor(encryptor Encryptor) *Issuer {
	return &Issuer{
		issuerName: i.issuerName,
		encryptor:  encryptor,
		signer:     i.signer,
		signingKey: i.signingKey,
		encryptKey: i.encryptKey,
	}
}

// WithSigner 返回设置了签名器的新 Issuer（链式调用）
func (i *Issuer) WithSigner(signer Signer) *Issuer {
	return &Issuer{
		issuerName: i.issuerName,
		encryptor:  i.encryptor,
		signer:     signer,
		signingKey: i.signingKey,
		encryptKey: i.encryptKey,
	}
}

// Issue 签发 token
// 使用 AccessToken 接口构建 token，通过成员变量 encryptor 加密用户信息，通过 signer 签名
func (i *Issuer) Issue(accessToken AccessToken) (string, error) {
	if i.signer == nil {
		return "", errors.New("signer not set")
	}

	// 构建 JWT Token
	token, err := accessToken.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 如果是 UserAccessToken，需要加密用户信息到 sub
	if uat, ok := accessToken.(*UserAccessToken); ok && uat.GetUser() != nil {
		if i.encryptor == nil {
			return "", errors.New("encryptor not set for UserAccessToken")
		}
		encryptedSub, err := i.encryptor.EncryptClaims(uat.GetUser())
		if err != nil {
			return "", fmt.Errorf("encrypt user claims: %w", err)
		}
		_ = token.Set(jwt.SubjectKey, encryptedSub)
	}

	// 签名
	signed, err := i.signer.Sign(token)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// IssueUserToken 签发用户访问令牌的便捷方法
func (i *Issuer) IssueUserToken(
	clientID, audience, scope string,
	ttl time.Duration,
	user *pkgtoken.Claims,
) (string, error) {
	uat := NewUserAccessToken(i.issuerName, clientID, audience, scope, ttl, user)
	return i.Issue(uat)
}

// IssueServiceToken 签发服务访问令牌的便捷方法
func (i *Issuer) IssueServiceToken(
	clientID, audience, scope string,
	ttl time.Duration,
) (string, error) {
	sat := NewServiceAccessToken(i.issuerName, clientID, audience, scope, ttl)
	// ServiceAccessToken 不需要加密，临时使用 NopEncryptor
	originalEncryptor := i.encryptor
	i.encryptor = NewNopEncryptor()
	defer func() { i.encryptor = originalEncryptor }()
	return i.Issue(sat)
}

// ========== 向后兼容的方法 ==========

// IssueWithDefaults 使用默认密钥签发 token（旧版兼容）
// Deprecated: 使用 Issue 替代
func (i *Issuer) IssueWithDefaults(claims *SubjectClaims, clientID string, scope string, ttl time.Duration) (string, error) {
	user := &pkgtoken.Claims{
		OpenID:   claims.OpenID,
		Nickname: claims.Nickname,
		Picture:  claims.Picture,
		Email:    claims.Email,
		Phone:    claims.Phone,
	}

	// 使用默认的 encryptor 和 signer
	originalEncryptor := i.encryptor
	originalSigner := i.signer
	i.encryptor = NewJWEEncryptor(i.encryptKey)
	i.signer = NewEdDSASigner(i.signingKey)
	defer func() {
		i.encryptor = originalEncryptor
		i.signer = originalSigner
	}()

	uat := NewUserAccessToken(i.issuerName, clientID, clientID, scope, ttl, user)
	return i.Issue(uat)
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
