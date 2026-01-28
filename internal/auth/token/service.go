package token

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/heliannuuthus/helios/internal/auth/cache"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
)

// Service Token 服务
// 负责签发 UAT/SAT、验证 CAT
type Service struct {
	issuerName string
	cache      *cache.Manager
}

// NewService 创建 Token 服务
func NewService(cacheManager *cache.Manager) *Service {
	return &Service{
		issuerName: config.GetIssuer(),
		cache:      cacheManager,
	}
}

// GetIssuerName 返回签发者名称
func (s *Service) GetIssuerName() string {
	return s.issuerName
}

// ============= 签发 =============

// Issue 签发 token
func (s *Service) Issue(ctx context.Context, accessToken AccessToken) (string, error) {
	switch t := accessToken.(type) {
	case *UserAccessToken:
		return s.issueUserToken(ctx, t)
	case *ServiceAccessToken:
		return s.issueServiceToken(ctx, t)
	default:
		return "", errors.New("unsupported token type")
	}
}

// issueUserToken 签发用户访问令牌
func (s *Service) issueUserToken(ctx context.Context, uat *UserAccessToken) (string, error) {
	// 1. 加密 user claims 到 sub
	if uat.GetUser() == nil {
		return "", errors.New("user claims required for UserAccessToken")
	}
	encryptedSub, err := s.encrypt(ctx, uat)
	if err != nil {
		return "", fmt.Errorf("encrypt user claims: %w", err)
	}

	// 2. 构建 JWT 并设置加密后的 sub
	token, err := uat.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}
	_ = token.Set(jwt.SubjectKey, encryptedSub)

	// 3. 签名
	signed, err := s.sign(ctx, token, uat.GetClientID())
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// issueServiceToken 签发服务访问令牌
func (s *Service) issueServiceToken(ctx context.Context, sat *ServiceAccessToken) (string, error) {
	// 1. 构建 JWT
	token, err := sat.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 2. 签名
	signed, err := s.sign(ctx, token, sat.GetClientID())
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// ============= 验证 =============

// CATClaims 验证 CAT 后返回的信息
type CATClaims struct {
	ClientID string // 应用 ID（sub）
	Audience string // 目标服务（aud）
	JTI      string // JWT ID
}

// VerifyCAT 验证 ClientAccessToken
// CAT 由应用使用其密钥签发，用于 Client-Credentials 流程
func (s *Service) VerifyCAT(ctx context.Context, tokenString string) (*CATClaims, error) {
	// 1. 解析 token 获取 sub
	unverified, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	clientID, ok := unverified.Subject()
	if !ok || clientID == "" {
		return nil, errors.New("missing sub (client_id)")
	}

	// 2. 获取应用密钥
	app, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	if len(app.Key) == 0 {
		return nil, errors.New("application has no key")
	}

	// 3. 验证签名
	key, err := jwk.Import(app.Key)
	if err != nil {
		return nil, fmt.Errorf("import app key: %w", err)
	}

	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.HS256(), key),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 4. 提取信息
	audVal, ok := token.Audience()
	var audience string
	if ok && len(audVal) > 0 {
		audience = audVal[0]
	}

	jti, _ := token.JwtID()

	return &CATClaims{
		ClientID: clientID,
		Audience: audience,
		JTI:      jti,
	}, nil
}

// ============= 内部方法 =============

// sign 签名 JWT
func (s *Service) sign(ctx context.Context, token jwt.Token, clientID string) ([]byte, error) {
	// 1. 获取应用信息
	app, err := s.cache.GetApplication(ctx, clientID)
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
	return jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), signKey))
}

// encrypt 加密用户信息
func (s *Service) encrypt(ctx context.Context, uat *UserAccessToken) (string, error) {
	// 1. 获取服务加密密钥
	svc, err := s.cache.GetService(ctx, uat.GetAudience())
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
