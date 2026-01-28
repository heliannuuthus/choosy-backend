package token

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Interpreter Token 解释器
// 负责验证和解释 token，提取身份信息
// 通过 KeyProvider 接口解耦密钥获取逻辑，支持多种密钥来源
type Interpreter struct {
	signKeyProvider    KeyProvider // 签名公钥提供者（根据 clientID 获取）
	encryptKeyProvider KeyProvider // 加密密钥提供者（根据 audience 获取）
}

// NewInterpreter 创建解释器
// signKeyProvider: 签名公钥提供者（根据 client_id 获取域公钥，用于验签）
// encryptKeyProvider: 加密密钥提供者（根据 audience 获取对称密钥，用于解密 sub）
func NewInterpreter(signKeyProvider, encryptKeyProvider KeyProvider) *Interpreter {
	return &Interpreter{
		signKeyProvider:    signKeyProvider,
		encryptKeyProvider: encryptKeyProvider,
	}
}

// Interpret 验证并解释 token，返回身份信息
// 流程：
// 1. 解析 JWT 获取 cli（client_id）和 aud（audience）
// 2. 验证签名（使用 cli 从 signKeyProvider 获取公钥）
// 3. 解密 sub（使用 aud 从 encryptKeyProvider 获取对称密钥）
func (i *Interpreter) Interpret(ctx context.Context, tokenString string) (*Claims, error) {
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

	// 2. 验证签名
	if err := i.verify(ctx, tokenString, clientID); err != nil {
		return nil, err
	}

	// 3. 解密 sub 获取用户信息
	encryptedSub, ok := token.Subject()
	if !ok {
		return nil, fmt.Errorf("%w: missing sub", ErrMissingClaims)
	}

	userClaims, err := i.decrypt(ctx, encryptedSub, audience)
	if err != nil {
		return nil, fmt.Errorf("decrypt sub: %w", err)
	}

	// 获取其他字段
	var scope string
	_ = token.Get("scope", &scope)

	issuer, _ := token.Issuer()
	issuedAt, _ := token.IssuedAt()
	expireAt, _ := token.Expiration()

	return &Claims{
		Issuer:   issuer,
		Audience: audience,
		IssuedAt: issuedAt,
		ExpireAt: expireAt,
		ClientID: clientID,
		Scope:    scope,
		OpenID:   userClaims.OpenID,
		Nickname: userClaims.Nickname,
		Picture:  userClaims.Picture,
		Email:    userClaims.Email,
		Phone:    userClaims.Phone,
	}, nil
}

// verify 验证 JWT 签名
func (i *Interpreter) verify(ctx context.Context, tokenString string, clientID string) error {
	publicKey, err := i.signKeyProvider.Get(ctx, clientID)
	if err != nil {
		return fmt.Errorf("get public key for client %s: %w", clientID, err)
	}

	_, err = jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), publicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	return nil
}

// decrypt 解密 JWE 获取用户信息
func (i *Interpreter) decrypt(ctx context.Context, encryptedSub string, audience string) (*Claims, error) {
	decryptKey, err := i.encryptKeyProvider.Get(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("%w: get key for audience %s: %v", ErrUnsupportedAudience, audience, err)
	}

	var data []byte
	if decryptKey == nil {
		// 没有解密密钥则直接解析 JSON
		data = []byte(encryptedSub)
	} else {
		decrypted, err := jwe.Decrypt([]byte(encryptedSub),
			jwe.WithKey(jwa.DIRECT(), decryptKey),
		)
		if err != nil {
			return nil, fmt.Errorf("decrypt failed: %w", err)
		}
		data = decrypted
	}

	var claims Claims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	return &claims, nil
}
