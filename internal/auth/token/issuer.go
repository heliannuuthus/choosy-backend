package token

import (
	"context"
	"errors"
	"fmt"

	"github.com/heliannuuthus/helios/internal/auth/cache"
	"github.com/heliannuuthus/helios/pkg/json"
	pkgtoken "github.com/heliannuuthus/helios/pkg/token"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// signer 内部签名器
type signer struct {
	cache *cache.HermesCache
}

// Sign 签名 JWT Token
// 通过 clientID 获取 Application -> domainID -> Domain -> SignKey
func (s *signer) Sign(ctx context.Context, token jwt.Token, clientID string) ([]byte, error) {
	// 1. 获取应用信息
	app, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	// 2. 获取域签名密钥
	domainWithKey, err := s.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}

	// 3. 解析签名密钥
	signKey, err := jwk.ParseKey(domainWithKey.SignKey)
	if err != nil {
		return nil, fmt.Errorf("parse sign key: %w", err)
	}

	// 4. 签名
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), signKey))
	if err != nil {
		return nil, fmt.Errorf("sign token: %w", err)
	}

	return signed, nil
}

// encryptor 内部加密器
type encryptor struct {
	cache *cache.HermesCache
}

// Encrypt 加密用户信息
// 通过 audience 获取 Service -> Key
func (e *encryptor) Encrypt(ctx context.Context, claims *pkgtoken.Claims, audience string) (string, error) {
	// 1. 获取服务加密密钥
	svc, err := e.cache.GetService(ctx, audience)
	if err != nil {
		return "", fmt.Errorf("get service key: %w", err)
	}

	// 2. 序列化 claims
	data, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	// 3. 导入密钥
	key, err := jwk.Import(svc.Key)
	if err != nil {
		return "", fmt.Errorf("import encrypt key: %w", err)
	}

	// 4. 加密
	encrypted, err := jwe.Encrypt(data,
		jwe.WithKey(jwa.DIRECT(), key),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", fmt.Errorf("jwe encrypt: %w", err)
	}

	return string(encrypted), nil
}

// Issuer Token 签发器
type Issuer struct {
	issuerName string
	cache      *cache.HermesCache
	signer     *signer
	encryptor  *encryptor
}

// NewIssuer 创建 Token 签发器
func NewIssuer(issuerName string, hermesCache *cache.HermesCache) *Issuer {
	return &Issuer{
		issuerName: issuerName,
		cache:      hermesCache,
		signer:     &signer{cache: hermesCache},
		encryptor:  &encryptor{cache: hermesCache},
	}
}

// GetIssuerName 返回签发者名称
func (i *Issuer) GetIssuerName() string {
	return i.issuerName
}

// Issue 签发 token
// 通过 switch 类型断言识别 UAT 或 SAT，执行不同的签发逻辑
func (i *Issuer) Issue(ctx context.Context, accessToken AccessToken) (string, error) {
	switch t := accessToken.(type) {
	case *UserAccessToken:
		return i.issueUserToken(ctx, t)
	case *ServiceAccessToken:
		return i.issueServiceToken(ctx, t)
	default:
		return "", errors.New("unsupported token type")
	}
}

// issueUserToken 签发用户访问令牌
func (i *Issuer) issueUserToken(ctx context.Context, uat *UserAccessToken) (string, error) {
	// 1. 构建 JWT
	token, err := uat.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 2. 加密 user claims 到 sub
	if uat.GetUser() == nil {
		return "", errors.New("user claims required for UserAccessToken")
	}
	encryptedSub, err := i.encryptor.Encrypt(ctx, uat.GetUser(), uat.GetAudience())
	if err != nil {
		return "", fmt.Errorf("encrypt user claims: %w", err)
	}
	_ = token.Set(jwt.SubjectKey, encryptedSub)

	// 3. 签名
	signed, err := i.signer.Sign(ctx, token, uat.GetClientID())
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// issueServiceToken 签发服务访问令牌
func (i *Issuer) issueServiceToken(ctx context.Context, sat *ServiceAccessToken) (string, error) {
	// 1. 构建 JWT（无 sub）
	token, err := sat.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 2. 签名
	signed, err := i.signer.Sign(ctx, token, sat.GetClientID())
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// VerifyAccessToken 验证 Access Token
// 自动从 token 中解析 audience 和 clientID，获取对应的密钥进行验证
func (i *Issuer) VerifyAccessToken(ctx context.Context, tokenString string) (*Identity, error) {
	// 1. 先解析 token（不验证）获取 aud 和 cli
	unverified, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	audVal, ok := unverified.Audience()
	if !ok || len(audVal) == 0 {
		return nil, errors.New("missing aud")
	}
	audience := audVal[0]

	var clientID string
	if err := unverified.Get("cli", &clientID); err != nil || clientID == "" {
		return nil, errors.New("missing cli")
	}

	// 2. 获取服务加密密钥（用于解密 sub）
	svc, err := i.cache.GetService(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("get service key: %w", err)
	}

	// 3. 通过 clientID 获取应用信息，进而获取 domain
	app, err := i.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	// 4. 获取域签名密钥（用于验签）
	domainWithKey, err := i.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("get domain key: %w", err)
	}

	// 5. 解析签名密钥
	signKey, err := jwk.ParseKey(domainWithKey.SignKey)
	if err != nil {
		return nil, fmt.Errorf("parse sign key: %w", err)
	}

	// 6. 验证签名
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), signKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 7. 获取加密的 sub
	encryptedSub, ok := token.Subject()
	if !ok {
		return nil, errors.New("missing sub")
	}

	// 8. 解密 sub
	claims, err := i.decryptClaims(encryptedSub, svc.Key)
	if err != nil {
		return nil, fmt.Errorf("decrypt sub: %w", err)
	}

	// 获取 scope
	var scope string
	_ = token.Get("scope", &scope)

	return &Identity{
		OpenID:   claims.OpenID,
		ClientID: clientID,
		Audience: audience,
		Scope:    scope,
		Nickname: claims.Nickname,
		Picture:  claims.Picture,
		Email:    claims.Email,
		Phone:    claims.Phone,
	}, nil
}

// decryptClaims 解密用户信息
func (i *Issuer) decryptClaims(encryptedSub string, decryptKey []byte) (*pkgtoken.Claims, error) {
	key, err := jwk.Import(decryptKey)
	if err != nil {
		return nil, fmt.Errorf("import decrypt key: %w", err)
	}

	decrypted, err := jwe.Decrypt([]byte(encryptedSub),
		jwe.WithKey(jwa.DIRECT(), key),
	)
	if err != nil {
		return nil, err
	}

	var claims pkgtoken.Claims
	if err := json.Unmarshal(decrypted, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
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
	return nil, errors.New("VerifyAccessTokenGlobal is deprecated, use Issuer.VerifyAccessToken instead")
}
