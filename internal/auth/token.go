package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/auth/secret"
	tokenpkg "github.com/heliannuuthus/helios/pkg/auth/token"
	"github.com/heliannuuthus/helios/pkg/kms"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"
)

// Key ID 前缀常量
const (
	keyPrefixDomain  = "domain"
	keyPrefixClient  = "client"
	keyPrefixService = "service"
)

// 构建 key ID 的辅助函数
func domainKeyID(domainID string) string   { return keyPrefixDomain + ":" + domainID }
func clientKeyID(clientID string) string   { return keyPrefixClient + ":" + clientID }
func serviceKeyID(serviceID string) string { return keyPrefixService + ":" + serviceID }

// parseKeyID 解析 key ID，返回前缀和标识符
func parseKeyID(id string) (prefix, identifier string, err error) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid key ID format: %s", id)
	}
	return parts[0], parts[1], nil
}

// newSecretEntry 创建 SecretEntry
func newSecretEntry(id string, value []byte) []*secret.SecretEntry {
	return []*secret.SecretEntry{{ID: id, Value: value, CreatedAt: time.Now()}}
}

// secretLoader 动态加载密钥的 Loader
type secretLoader struct {
	db *gorm.DB
}

func (l *secretLoader) Load(ctx context.Context, id string) ([]*secret.SecretEntry, error) {
	prefix, identifier, err := parseKeyID(id)
	if err != nil {
		return nil, err
	}

	switch prefix {
	case keyPrefixDomain:
		keyBytes, err := config.GetDomainSignKey(identifier)
		if err != nil {
			return nil, fmt.Errorf("load domain sign key: %w", err)
		}
		return newSecretEntry(id, keyBytes), nil

	case keyPrefixClient:
		var client Client
		if err := l.db.WithContext(ctx).Where("client_id = ?", identifier).First(&client).Error; err != nil {
			return nil, fmt.Errorf("client not found: %w", err)
		}
		keyBytes, err := config.GetDomainEncryptKey(string(client.Domain))
		if err != nil {
			return nil, fmt.Errorf("load domain encrypt key: %w", err)
		}
		return newSecretEntry(id, keyBytes), nil

	case keyPrefixService:
		var service models.Service
		if err := l.db.WithContext(ctx).Where("service_id = ?", identifier).First(&service).Error; err != nil {
			return nil, fmt.Errorf("service not found: %w", err)
		}
		serviceKey, err := l.decryptServiceKey(&service)
		if err != nil {
			return nil, err
		}
		return newSecretEntry(id, serviceKey), nil

	default:
		return nil, fmt.Errorf("unknown key prefix: %s", prefix)
	}
}

// decryptServiceKey 解密服务密钥
func (l *secretLoader) decryptServiceKey(service *models.Service) ([]byte, error) {
	domainEncryptKey, err := config.GetDomainEncryptKey(service.DomainID)
	if err != nil {
		return nil, fmt.Errorf("get domain encrypt key: %w", err)
	}

	encryptedKeyBytes, err := base64.StdEncoding.DecodeString(service.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted key: %w", err)
	}

	return kms.DecryptAESGCM(domainEncryptKey, encryptedKeyBytes, service.ServiceID)
}

// TokenManager Token 管理器（嵌入 tokenpkg.Manager）
type TokenManager struct {
	*tokenpkg.Manager
	issuer string
	db     *gorm.DB
}

// NewTokenManager 创建 Token 管理器
func NewTokenManager(db *gorm.DB) (*TokenManager, error) {
	return &TokenManager{
		Manager: tokenpkg.NewManager(&secretLoader{db: db}),
		issuer:  config.GetIssuer(),
		db:      db,
	}, nil
}

// getClient 查询客户端
func (tm *TokenManager) getClient(ctx context.Context, clientID string) (*Client, error) {
	var client Client
	if err := tm.db.WithContext(ctx).Where("client_id = ?", clientID).First(&client).Error; err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}
	return &client, nil
}

// CreateAccessToken 创建 Access Token
// sub 字段包含加密的用户信息（openid, nickname, picture, email, phone）
func (tm *TokenManager) CreateAccessToken(claims *SubjectClaims, client *Client, scope string, ttl time.Duration) (string, error) {
	ctx := context.Background()

	encryptedSub, err := tm.encryptSubjectClaims(ctx, claims, clientKeyID(client.ClientID))
	if err != nil {
		return "", fmt.Errorf("encrypt sub: %w", err)
	}

	return tm.Signer(domainKeyID(string(client.Domain))).Sign(
		ctx, tm.issuer, encryptedSub, client.ClientID, int(ttl.Seconds()), "scope", scope,
	)
}

// VerifyAccessToken 验证 Access Token，返回身份信息
func (tm *TokenManager) VerifyAccessToken(tokenString string) (*Identity, error) {
	ctx := context.Background()

	// 先解析 token 获取 clientID（不验证签名）
	clientID, err := tm.extractClientID(tokenString)
	if err != nil {
		return nil, err
	}

	client, err := tm.getClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// 验证 JWT
	verifiedToken, err := tm.Verifier(domainKeyID(string(client.Domain))).Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 获取并解密 sub
	encryptedSub, ok := verifiedToken.Subject()
	if !ok {
		return nil, errors.New("missing sub")
	}

	claims, err := tm.decryptSubjectClaims(ctx, encryptedSub, clientKeyID(clientID))
	if err != nil {
		return nil, fmt.Errorf("decrypt sub: %w", err)
	}

	// 构造 AccessToken 并设置用户信息
	accessToken := tokenpkg.NewAccessToken(verifiedToken).
		WithUserInfo(claims.OpenID, claims.Nickname, claims.Picture, claims.Email, claims.Phone)

	return &Identity{
		UserID:   accessToken.Subject,
		Scope:    accessToken.Scope,
		Nickname: accessToken.Nickname,
		Picture:  accessToken.Picture,
		Email:    accessToken.Email,
		Phone:    accessToken.Phone,
	}, nil
}

// extractClientID 从 token 中提取 clientID（不验证签名）
func (tm *TokenManager) extractClientID(tokenString string) (string, error) {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return "", fmt.Errorf("parse token: %w", err)
	}

	aud, ok := token.Audience()
	if !ok || len(aud) == 0 {
		return "", errors.New("missing audience (clientID)")
	}
	return aud[0], nil
}

// ParseAccessTokenUnverified 解析 Token 但不验证（用于获取 claims）
func (tm *TokenManager) ParseAccessTokenUnverified(tokenString string) (aud, iss string, exp, iat int64, scope string, err error) {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return
	}

	if v, ok := token.Audience(); ok && len(v) > 0 {
		aud = v[0]
	}
	iss, _ = token.Issuer()
	if v, ok := token.Expiration(); ok {
		exp = v.Unix()
	}
	if v, ok := token.IssuedAt(); ok {
		iat = v.Unix()
	}
	_ = token.Get("scope", &scope)
	return
}

// encryptSubjectClaims 加密用户信息
// encryptorID 格式：client:{clientID} 或 service:{serviceID}
func (tm *TokenManager) encryptSubjectClaims(ctx context.Context, claims *SubjectClaims, encryptorID string) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// 尝试使用 Encryptor 加密，如果失败（未配置加密密钥）则返回 JSON
	encrypted, err := tm.Encryptor(encryptorID).Encrypt(ctx, data, jwa.A256GCM())
	if err != nil {
		// 如果加密失败（可能是未配置加密密钥），返回 JSON
		return string(data), nil
	}

	return string(encrypted), nil
}

// decryptSubjectClaims 解密用户信息
// decryptorID 格式：client:{clientID} 或 service:{serviceID}
func (tm *TokenManager) decryptSubjectClaims(ctx context.Context, encryptedSub string, decryptorID string) (*SubjectClaims, error) {
	// 尝试使用 Decryptor 解密，如果失败（未配置解密密钥或数据未加密）则尝试直接解析 JSON
	decrypted, err := tm.Decryptor(decryptorID).Decrypt(ctx, []byte(encryptedSub))
	if err != nil {
		// 如果解密失败，可能是未加密的 JSON，尝试直接解析
		decrypted = []byte(encryptedSub)
	}

	var claims SubjectClaims
	if err := json.Unmarshal(decrypted, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// VerifyServiceJWT 验证 Service JWT（用于 introspect）
func (tm *TokenManager) VerifyServiceJWT(tokenString string, serviceKey []byte) (serviceID string, jti string, err error) {
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

// randomBytes 生成随机字节
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// GenerateAuthorizationCode 生成授权码
func GenerateAuthorizationCode() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(32))
}

// GenerateSessionID 生成会话 ID
func GenerateSessionID() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(16))
}

// GenerateRefreshToken 生成 Refresh Token
func GenerateRefreshToken() string {
	return hex.EncodeToString(randomBytes(32))
}

// VerifyCodeChallenge 验证 PKCE（只支持 S256）
func VerifyCodeChallenge(method CodeChallengeMethod, challenge, verifier string) bool {
	if method != CodeChallengeMethodS256 {
		return false
	}
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:]) == challenge
}

// CreateServiceJWT 创建服务 JWT
// userID 非空时为用户令牌，空字符串时为服务令牌
func (tm *TokenManager) CreateServiceJWT(serviceID, userID, scope string, serviceKey []byte, ttl time.Duration) (string, error) {
	now := time.Now()

	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, tm.issuer)
	_ = token.Set(jwt.AudienceKey, serviceID)
	_ = token.Set(jwt.IssuedAtKey, now.Unix())
	_ = token.Set(jwt.ExpirationKey, now.Add(ttl).Unix())
	_ = token.Set(jwt.NotBeforeKey, now.Unix())
	_ = token.Set(jwt.JwtIDKey, hex.EncodeToString(randomBytes(16)))
	_ = token.Set("scope", scope)

	if userID != "" {
		_ = token.Set(jwt.SubjectKey, userID)
	}

	key, err := jwk.Import(serviceKey)
	if err != nil {
		return "", fmt.Errorf("import service key: %w", err)
	}

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), key))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return string(signedToken), nil
}

// CreateRefreshToken 创建 Refresh Token（简化版，返回 token 字符串）
func (tm *TokenManager) CreateRefreshToken(_, _, _ string, _ time.Duration) (string, error) {
	return GenerateRefreshToken(), nil
}
