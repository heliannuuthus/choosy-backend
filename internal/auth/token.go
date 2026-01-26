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
	"time"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Token 验证错误
var (
	ErrUnsupportedAudience = errors.New("unsupported audience")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrMissingClaims       = errors.New("missing required claims")
)

// TokenManager Token 管理器
// 支持 token 的签发（Auth 模块使用）
type TokenManager struct {
	issuer     string
	signingKey jwk.Key // 默认签名密钥（用于旧接口兼容）
	encryptKey jwk.Key // 默认加密密钥（用于旧接口兼容）
}

// NewTokenManager 创建 Token 管理器
func NewTokenManager() (*TokenManager, error) {
	tm := &TokenManager{
		issuer: config.GetString("auth.issuer"),
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
		tm.signingKey = key
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
		tm.encryptKey = key
	}

	return tm, nil
}

// CreateAccessToken 创建 Access Token（兼容旧接口）
// sub 字段包含加密的用户信息（openid, nickname, picture, email, phone）
// Deprecated: 使用 CreateAccessTokenV2 替代
func (tm *TokenManager) CreateAccessToken(claims *SubjectClaims, clientID string, scope string, ttl time.Duration) (string, error) {
	now := time.Now()

	// 加密 sub（用户信息）
	encryptedSub, err := tm.encryptSubjectClaims(claims)
	if err != nil {
		return "", fmt.Errorf("encrypt sub: %w", err)
	}

	// 创建 JWT
	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, tm.issuer)
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
	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), tm.signingKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signedToken), nil
}

// CreateAccessTokenV2 创建 Access Token（新版本）
// Deprecated: 使用 Issuer.Issue 替代
func (tm *TokenManager) CreateAccessTokenV2(
	claims *SubjectClaims,
	clientID string,
	audience string,
	serviceEncryptKey jwk.Key,
	signKey jwk.Key,
	scope string,
	ttl time.Duration,
) (string, error) {
	issuer := NewIssuer(tm.issuer)
	return issuer.Issue(claims, clientID, audience, serviceEncryptKey, signKey, scope, ttl)
}

// VerifyAccessToken 验证 Access Token，返回完整身份信息
func (tm *TokenManager) VerifyAccessToken(tokenString string) (*Identity, error) {
	// 验证签名
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), tm.signingKey),
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
	claims, err := tm.decryptSubjectClaims(encryptedSub)
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
func (tm *TokenManager) ParseAccessTokenUnverified(tokenString string) (aud string, iss string, exp int64, iat int64, scope string, err error) {
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

// encryptSubjectClaims 加密用户信息
func (tm *TokenManager) encryptSubjectClaims(claims *SubjectClaims) (string, error) {
	if tm.encryptKey == nil {
		// 没有加密密钥则返回 JSON
		data, err := json.Marshal(claims)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	data, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encrypted, err := jwe.Encrypt(data,
		jwe.WithKey(jwa.DIRECT(), tm.encryptKey),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", err
	}

	return string(encrypted), nil
}

// decryptSubjectClaims 解密用户信息
func (tm *TokenManager) decryptSubjectClaims(encryptedSub string) (*SubjectClaims, error) {
	var data []byte

	if tm.encryptKey == nil {
		// 没有加密密钥则直接解析 JSON
		data = []byte(encryptedSub)
	} else {
		decrypted, err := jwe.Decrypt([]byte(encryptedSub),
			jwe.WithKey(jwa.DIRECT(), tm.encryptKey),
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

// GenerateAuthorizationCode 生成授权码
func GenerateAuthorizationCode() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// GenerateSessionID 生成会话 ID
func GenerateSessionID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// VerifyCodeChallenge 验证 PKCE（只支持 S256）
func VerifyCodeChallenge(method CodeChallengeMethod, challenge, verifier string) bool {
	if method != CodeChallengeMethodS256 {
		return false
	}
	hash := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	return computed == challenge
}

// VerifyAccessToken 兼容旧接口（全局函数）
func VerifyAccessToken(tokenString string) (*Identity, error) {
	tm, err := NewTokenManager()
	if err != nil {
		return nil, err
	}
	return tm.VerifyAccessToken(tokenString)
}

// ExplainToken 验证并解释 token，返回完整身份信息
// Deprecated: 使用 pkg/token.Verifier.Verify 替代
func ExplainToken(ctx context.Context, tokenString string, expectedAudience string, decryptKey jwk.Key, getPublicKey func(ctx context.Context, clientID string) (jwk.Key, error)) (*Identity, error) {
	// 1. 解析 JWT（不验证）获取 claims
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	// 获取 aud (audience/service_id)
	audVal, ok := token.Audience()
	if !ok || len(audVal) == 0 {
		return nil, fmt.Errorf("%w: missing aud", ErrMissingClaims)
	}
	audience := audVal[0]

	// 检查 audience 是否匹配
	if audience != expectedAudience {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrUnsupportedAudience, expectedAudience, audience)
	}

	// 获取 cli (client_id)
	var clientID string
	if err := token.Get("cli", &clientID); err != nil || clientID == "" {
		return nil, fmt.Errorf("%w: missing cli", ErrMissingClaims)
	}

	// 2. 获取域公钥验证签名
	publicKey, err := getPublicKey(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	// 验证签名
	_, err = jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), publicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	// 3. 解密 sub 获取用户信息
	encryptedSub, ok := token.Subject()
	if !ok {
		return nil, fmt.Errorf("%w: missing sub", ErrMissingClaims)
	}

	claims, err := decryptSubjectClaimsLegacy(encryptedSub, decryptKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt sub: %w", err)
	}

	// 获取其他字段
	var scope string
	_ = token.Get("scope", &scope)

	issuer, _ := token.Issuer()
	issuedAt, _ := token.IssuedAt()
	expireAt, _ := token.Expiration()

	return &Identity{
		UserID:   claims.OpenID,
		ClientID: clientID,
		Audience: audience,
		Scope:    scope,
		Nickname: claims.Nickname,
		Picture:  claims.Picture,
		Email:    claims.Email,
		Phone:    claims.Phone,
		Issuer:   issuer,
		IssuedAt: issuedAt,
		ExpireAt: expireAt,
	}, nil
}

// decryptSubjectClaimsLegacy 使用指定密钥解密用户信息（旧版兼容）
func decryptSubjectClaimsLegacy(encryptedSub string, decryptKey jwk.Key) (*SubjectClaims, error) {
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

