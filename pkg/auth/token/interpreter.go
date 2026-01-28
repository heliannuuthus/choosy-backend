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

// VerifiedToken 验证后的 token 信息（不含解密的用户信息）
type VerifiedToken struct {
	Issuer   string
	Audience string
	ClientID string
	Scope    string
	Subject  string // 加密的 sub（未解密）
	Token    jwt.Token
}

// Verify 只验证签名，不解密 sub
// 适用于只需要验证凭证有效性的场景
func (i *Interpreter) Verify(ctx context.Context, tokenString string) (*VerifiedToken, error) {
	// 1. 解析 JWT（不验证）获取 claims
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	// 获取 cli (client_id)
	var clientID string
	if err := token.Get("cli", &clientID); err != nil || clientID == "" {
		return nil, fmt.Errorf("%w: missing cli", ErrMissingClaims)
	}

	// 2. 获取公钥并验证签名
	publicKey, err := i.signKeyProvider.Get(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get public key for client %s: %w", clientID, err)
	}

	_, err = jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), publicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	// 3. 提取基本信息
	var audience string
	if audVal, ok := token.Audience(); ok && len(audVal) > 0 {
		audience = audVal[0]
	}

	var scope string
	_ = token.Get("scope", &scope)

	issuer, _ := token.Issuer()
	subject, _ := token.Subject()

	return &VerifiedToken{
		Issuer:   issuer,
		Audience: audience,
		ClientID: clientID,
		Scope:    scope,
		Subject:  subject,
		Token:    token,
	}, nil
}

// Decrypt 解密 sub 获取用户信息
// 通常在 Verify 之后调用，用于需要用户信息的场景
func (i *Interpreter) Decrypt(ctx context.Context, vt *VerifiedToken) (*Claims, error) {
	if vt.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrMissingClaims)
	}

	decryptKey, err := i.encryptKeyProvider.Get(ctx, vt.Audience)
	if err != nil {
		return nil, fmt.Errorf("%w: get key for audience %s: %v", ErrUnsupportedAudience, vt.Audience, err)
	}

	var data []byte
	if decryptKey == nil {
		data = []byte(vt.Subject)
	} else {
		decrypted, err := jwe.Decrypt([]byte(vt.Subject),
			jwe.WithKey(jwa.DIRECT(), decryptKey),
		)
		if err != nil {
			return nil, fmt.Errorf("decrypt failed: %w", err)
		}
		data = decrypted
	}

	var userClaims Claims
	if err := json.Unmarshal(data, &userClaims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	issuedAt, _ := vt.Token.IssuedAt()
	expireAt, _ := vt.Token.Expiration()

	return &Claims{
		Issuer:   vt.Issuer,
		Audience: vt.Audience,
		IssuedAt: issuedAt,
		ExpireAt: expireAt,
		ClientID: vt.ClientID,
		Scope:    vt.Scope,
		OpenID:   userClaims.OpenID,
		Nickname: userClaims.Nickname,
		Picture:  userClaims.Picture,
		Email:    userClaims.Email,
		Phone:    userClaims.Phone,
	}, nil
}

// Interpret 验证并解释 token，返回完整身份信息
// 完整流程：验证签名 + 解密 sub
func (i *Interpreter) Interpret(ctx context.Context, tokenString string) (*Claims, error) {
	vt, err := i.Verify(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	return i.Decrypt(ctx, vt)
}
