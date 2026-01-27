package token

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Explainer Token 解释器
// 负责验证和解释 token，提取身份信息
type Explainer struct {
	publicKeyProvider KeyProvider // 获取公钥（验签）
	secretProvider    KeyProvider // 获取解密密钥
}

// NewExplainer 创建解释器
// publicKeyProvider: 公钥提供者（根据 client_id 获取域公钥）
// secretProvider: 解密密钥提供者（根据 audience 获取对称密钥）
func NewExplainer(publicKeyProvider, secretProvider KeyProvider) *Explainer {
	return &Explainer{
		publicKeyProvider: publicKeyProvider,
		secretProvider:    secretProvider,
	}
}

// Explain 验证并解释 token，返回身份信息
// 流程：
// 1. 解析 JWT 获取 cli（client_id）和 aud（audience）
// 2. 从 secretProvider 获取 aud 对应的解密密钥
// 3. 从 publicKeyProvider 获取 cli 对应的公钥
// 4. 验证签名 + 解密 sub
func (e *Explainer) Explain(ctx context.Context, tokenString string) (*Identity, error) {
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

	// 获取 cli (client_id)
	var clientID string
	if err := token.Get("cli", &clientID); err != nil || clientID == "" {
		return nil, fmt.Errorf("%w: missing cli", ErrMissingClaims)
	}

	// 2. 获取解密密钥
	decryptKey, err := e.secretProvider.Get(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAudience, err)
	}

	// 3. 获取域公钥验证签名
	publicKey, err := e.publicKeyProvider.Get(ctx, clientID)
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

	// 4. 解密 sub 获取用户信息
	encryptedSub, ok := token.Subject()
	if !ok {
		return nil, fmt.Errorf("%w: missing sub", ErrMissingClaims)
	}

	claims, err := decryptSubjectClaims(encryptedSub, decryptKey)
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

// decryptSubjectClaims 使用指定密钥解密用户信息
func decryptSubjectClaims(encryptedSub string, decryptKey jwk.Key) (*SubjectClaims, error) {
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

// Verifier 类型别名（向后兼容）
// Deprecated: 使用 Explainer 替代
type Verifier = Explainer

// NewVerifier 向后兼容
// Deprecated: 使用 NewExplainer 替代
func NewVerifier(publicKeyProvider, secretProvider KeyProvider) *Verifier {
	return NewExplainer(publicKeyProvider, secretProvider)
}

// Verify 向后兼容
// Deprecated: 使用 Explain 替代
func (e *Explainer) Verify(ctx context.Context, tokenString string) (*Identity, error) {
	return e.Explain(ctx, tokenString)
}
