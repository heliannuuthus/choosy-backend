package token

import (
	"context"
	"errors"
	"fmt"

	"github.com/heliannuuthus/helios/internal/auth/cache"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
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
// 通过 AccessToken.GetClientID() 获取 Application -> domainID -> Domain -> SignKey
func (s *signer) Sign(ctx context.Context, accessToken AccessToken) ([]byte, error) {
	token, err := accessToken.Build()
	if err != nil {
		return nil, fmt.Errorf("build token: %w", err)
	}

	// 1. 获取应用信息
	app, err := s.cache.GetApplication(ctx, accessToken.GetClientID())
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	// 2. 获取域签名密钥
	domain, err := s.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}

	// 3. 解析签名密钥
	signKey, err := jwk.ParseKey(domain.SignKey)
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
// 通过 UserAccessToken.GetAudience() 获取 Service -> Key
func (e *encryptor) Encrypt(ctx context.Context, uat *UserAccessToken) (string, error) {
	// 1. 获取服务加密密钥
	svc, err := e.cache.GetService(ctx, uat.GetAudience())
	if err != nil {
		return "", fmt.Errorf("get service key: %w", err)
	}

	// 2. 序列化 claims
	data, err := json.Marshal(uat.GetUser())
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
func NewIssuer(hermesCache *cache.HermesCache) *Issuer {
	return &Issuer{
		issuerName: config.GetIssuer(),
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
	encryptedSub, err := i.encryptor.Encrypt(ctx, uat)
	if err != nil {
		return "", fmt.Errorf("encrypt user claims: %w", err)
	}
	_ = token.Set(jwt.SubjectKey, encryptedSub)

	// 3. 签名
	signed, err := i.signer.Sign(ctx, uat)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// issueServiceToken 签发服务访问令牌
func (i *Issuer) issueServiceToken(ctx context.Context, sat *ServiceAccessToken) (string, error) {
	signed, err := i.signer.Sign(ctx, sat)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// ClientAccessTokenClaims 验证 CAT 后返回的信息
type ClientAccessTokenClaims struct {
	ClientID string // 应用 ID（sub）
	Audience string // 目标服务（aud）
	JTI      string // JWT ID
}

// VerifyClientAccessToken 验证 ClientAccessToken
// CAT 是客户端使用应用密钥签发的 JWS，用于 Client-Credentials 流程
// 通过 sub（clientID）获取 Application -> Key 进行验签
func (i *Issuer) VerifyClientAccessToken(ctx context.Context, tokenString string) (*ClientAccessTokenClaims, error) {
	// 1. 先解析 token（不验证）获取 sub
	unverified, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	clientID, ok := unverified.Subject()
	if !ok || clientID == "" {
		return nil, errors.New("missing sub (client_id)")
	}

	// 2. 获取应用信息和密钥
	app, err := i.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	// 3. 检查应用是否有密钥
	if len(app.Key) == 0 {
		return nil, errors.New("application has no key")
	}

	// 4. 导入密钥
	key, err := jwk.Import(app.Key)
	if err != nil {
		return nil, fmt.Errorf("import app key: %w", err)
	}

	// 5. 验证签名（CAT 使用 HS256）
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.HS256(), key),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 6. 提取信息
	audVal, ok := token.Audience()
	var audience string
	if ok && len(audVal) > 0 {
		audience = audVal[0]
	}

	jti, _ := token.JwtID()

	return &ClientAccessTokenClaims{
		ClientID: clientID,
		Audience: audience,
		JTI:      jti,
	}, nil
}

// VerifyServiceJWT 验证 Service JWT（用于 introspect）
// Service JWT 本质上也是 CAT 的一种形式，由 Service 使用其密钥签发
func (i *Issuer) VerifyServiceJWT(ctx context.Context, tokenString string) (*ClientAccessTokenClaims, error) {
	// 1. 解析 JWT 获取 service_id（不验证签名）
	unverified, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	serviceID, ok := unverified.Subject()
	if !ok || serviceID == "" {
		return nil, errors.New("missing sub (service_id)")
	}

	// 2. 从缓存获取 Service 密钥
	svc, err := i.cache.GetService(ctx, serviceID)
	if err != nil {
		return nil, fmt.Errorf("get service: %w", err)
	}

	// 3. 导入密钥
	key, err := jwk.Import(svc.Key)
	if err != nil {
		return nil, fmt.Errorf("import service key: %w", err)
	}

	// 4. 验证签名（Service JWT 使用 HS256）
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.HS256(), key),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 5. 提取信息
	audVal, ok := token.Audience()
	var audience string
	if ok && len(audVal) > 0 {
		audience = audVal[0]
	}

	jti, _ := token.JwtID()

	return &ClientAccessTokenClaims{
		ClientID: serviceID, // Service ID 放在 ClientID 字段
		Audience: audience,
		JTI:      jti,
	}, nil
}

// ParseAccessTokenUnverified 解析 Access Token（不验证）
// 用于 introspect 场景：auth 服务只需解析 token 信息，不需要验证
func (i *Issuer) ParseAccessTokenUnverified(tokenString string) (*AccessTokenInfo, error) {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	info := &AccessTokenInfo{}

	if audVal, ok := token.Audience(); ok && len(audVal) > 0 {
		info.Audience = audVal[0]
	}
	if issVal, ok := token.Issuer(); ok {
		info.Issuer = issVal
	}
	if expVal, ok := token.Expiration(); ok {
		info.Exp = expVal.Unix()
	}
	if iatVal, ok := token.IssuedAt(); ok {
		info.Iat = iatVal.Unix()
	}
	_ = token.Get("scope", &info.Scope)
	_ = token.Get("cli", &info.ClientID)

	// 获取 sub（可能是加密的用户信息，也可能不存在）
	if sub, ok := token.Subject(); ok {
		info.Sub = sub
	}

	return info, nil
}

// AccessTokenInfo 解析 AccessToken 后的信息（不含验证）
type AccessTokenInfo struct {
	Issuer   string
	Audience string
	ClientID string
	Scope    string
	Sub      string // 可能是加密的用户信息
	Exp      int64
	Iat      int64
}
