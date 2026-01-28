package token

import (
	"context"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/heliannuuthus/helios/pkg/json"
)

// ============= Interpreter =============

// Interpreter Token 解释器
// 负责验证和解释 token，提取身份信息
// 内部缓存 Verifier 和 decryptor 实例，避免重复构造
type Interpreter struct {
	signKeyProvider    KeyProvider // 签名公钥提供者（根据 clientID 获取）
	encryptKeyProvider KeyProvider // 加密密钥提供者（根据 audience 获取）

	verifiers  map[string]*Verifier  // 缓存：key = clientID
	decryptors map[string]*decryptor // 缓存：key = audience
	mu         sync.RWMutex
}

// NewInterpreter 创建解释器
func NewInterpreter(signKeyProvider, encryptKeyProvider KeyProvider) *Interpreter {
	return &Interpreter{
		signKeyProvider:    signKeyProvider,
		encryptKeyProvider: encryptKeyProvider,
		verifiers:          make(map[string]*Verifier),
		decryptors:         make(map[string]*decryptor),
	}
}

// Verifier 获取或创建绑定特定 clientID 的 Verifier
func (i *Interpreter) Verifier(clientID string) *Verifier {
	return getOrCreate(&i.mu, i.verifiers, clientID, func() *Verifier {
		return &Verifier{
			keyProvider: i.signKeyProvider,
			clientID:    clientID,
		}
	})
}

// Interpret 验证并解释 token，返回完整身份信息（含用户信息）
func (i *Interpreter) Interpret(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := parseToken(tokenString)
	if err != nil {
		return nil, err
	}

	clientID, err := extractClientID(token)
	if err != nil {
		return nil, err
	}

	claims, err := i.Verifier(clientID).Verify(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if err := i.getDecryptor(claims.Audience).decrypt(ctx, claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// Verify 只验证签名，不解密 sub（便捷方法）
// 返回的 Claims 中用户信息字段为空
func (i *Interpreter) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := parseToken(tokenString)
	if err != nil {
		return nil, err
	}

	clientID, err := extractClientID(token)
	if err != nil {
		return nil, err
	}

	return i.Verifier(clientID).Verify(ctx, tokenString)
}

// getDecryptor 获取或创建绑定特定 audience 的 decryptor
func (i *Interpreter) getDecryptor(audience string) *decryptor {
	return getOrCreate(&i.mu, i.decryptors, audience, func() *decryptor {
		return &decryptor{
			keyProvider: i.encryptKeyProvider,
			audience:    audience,
		}
	})
}

// ============= Verifier =============

// Verifier 负责验证 JWT 签名
// 绑定特定的 clientID，只做验签不解密
type Verifier struct {
	keyProvider KeyProvider
	clientID    string
}

// Verify 验证 token 签名，返回 Claims（用户信息字段为空）
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	token, err := parseToken(tokenString)
	if err != nil {
		return nil, err
	}

	clientID, err := extractClientID(token)
	if err != nil {
		return nil, err
	}

	if clientID != v.clientID {
		return nil, fmt.Errorf("%w: client_id mismatch, expected %s, got %s",
			ErrInvalidSignature, v.clientID, clientID)
	}

	if err := v.verifySignature(ctx, tokenString); err != nil {
		return nil, err
	}

	return extractClaims(token), nil
}

func (v *Verifier) verifySignature(ctx context.Context, tokenString string) error {
	publicKey, err := v.keyProvider.Get(ctx, v.clientID)
	if err != nil {
		return fmt.Errorf("get public key for client %s: %w", v.clientID, err)
	}

	_, err = jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), publicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	return nil
}

// ============= 内部实现 =============

// decryptor 负责解密 subject
type decryptor struct {
	keyProvider KeyProvider
	audience    string
}

func (d *decryptor) decrypt(ctx context.Context, claims *Claims) error {
	if claims.Subject == "" {
		return fmt.Errorf("%w: empty subject", ErrMissingClaims)
	}

	decryptKey, err := d.keyProvider.Get(ctx, d.audience)
	if err != nil {
		return fmt.Errorf("%w: get key for audience %s: %w", ErrUnsupportedAudience, d.audience, err)
	}

	data, err := d.decryptData(claims.Subject, decryptKey)
	if err != nil {
		return err
	}

	return d.fillUserInfo(claims, data)
}

func (d *decryptor) decryptData(subject string, key any) ([]byte, error) {
	if key == nil {
		return []byte(subject), nil
	}

	decrypted, err := jwe.Decrypt([]byte(subject), jwe.WithKey(jwa.DIRECT(), key))
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return decrypted, nil
}

func (d *decryptor) fillUserInfo(claims *Claims, data []byte) error {
	var userClaims Claims
	if err := json.Unmarshal(data, &userClaims); err != nil {
		return fmt.Errorf("unmarshal claims: %w", err)
	}

	claims.OpenID = userClaims.OpenID
	claims.Nickname = userClaims.Nickname
	claims.Picture = userClaims.Picture
	claims.Email = userClaims.Email
	claims.Phone = userClaims.Phone

	return nil
}

// ============= 辅助函数 =============

func parseToken(tokenString string) (jwt.Token, error) {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	return token, nil
}

func extractClientID(token jwt.Token) (string, error) {
	var clientID string
	if err := token.Get("cli", &clientID); err != nil || clientID == "" {
		return "", fmt.Errorf("%w: missing cli", ErrMissingClaims)
	}
	return clientID, nil
}

func extractClaims(token jwt.Token) *Claims {
	var audience string
	if audVal, ok := token.Audience(); ok && len(audVal) > 0 {
		audience = audVal[0]
	}

	var scope, clientID string
	_ = token.Get("scope", &scope)
	_ = token.Get("cli", &clientID)

	issuer, _ := token.Issuer()
	subject, _ := token.Subject()
	issuedAt, _ := token.IssuedAt()
	expireAt, _ := token.Expiration()

	return &Claims{
		Issuer:   issuer,
		Audience: audience,
		IssuedAt: issuedAt,
		ExpireAt: expireAt,
		ClientID: clientID,
		Scope:    scope,
		Subject:  subject,
	}
}

func getOrCreate[T any](mu *sync.RWMutex, cache map[string]*T, key string, create func() *T) *T {
	mu.RLock()
	if v, ok := cache[key]; ok {
		mu.RUnlock()
		return v
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()

	if v, ok := cache[key]; ok {
		return v
	}

	v := create()
	cache[key] = v
	return v
}
