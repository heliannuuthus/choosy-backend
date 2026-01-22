package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ============= 密钥集合构建 =============

// BuildKeySet 从字节数组列表构建 jwk.Set（泛型版本）
func BuildKeySet[T interface{ GetValue() []byte }](entries []T) (jwk.Set, error) {
	if len(entries) == 0 {
		return nil, errors.New("entries list is empty")
	}

	set := jwk.NewSet()
	for i, entry := range entries {
		jwkKey, err := ImportKey(entry.GetValue())
		if err != nil {
			return nil, fmt.Errorf("import key[%d]: %w", i, err)
		}

		// 如果没有 kid，自动生成一个
		if kid, ok := jwkKey.KeyID(); !ok || kid == "" {
			if err := jwkKey.Set(jwk.KeyIDKey, fmt.Sprintf("key-%d", i)); err != nil {
				return nil, fmt.Errorf("set kid for key[%d]: %w", i, err)
			}
		}

		if err := set.AddKey(jwkKey); err != nil {
			return nil, fmt.Errorf("add key[%d] to set: %w", i, err)
		}
	}
	return set, nil
}

// bytesWrapper 包装 []byte 以实现 GetValue 接口
type bytesWrapper []byte

func (b bytesWrapper) GetValue() []byte { return b }

// BuildKeySetFromBytes 从字节数组列表构建 jwk.Set
func BuildKeySetFromBytes(keyBytesList [][]byte) (jwk.Set, error) {
	wrapped := make([]bytesWrapper, len(keyBytesList))
	for i, kb := range keyBytesList {
		wrapped[i] = bytesWrapper(kb)
	}
	return BuildKeySet(wrapped)
}

// ImportKey 统一的密钥导入接口
// 支持的类型：
//   - []byte: 原始密钥字节
//   - string: 密钥字符串（JSON JWK 或原始字符串）
//   - jwk.Key: 直接返回
//   - *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey 等原始密钥类型
func ImportKey(key any) (jwk.Key, error) {
	if key == nil {
		return nil, errors.New("key is nil")
	}

	switch v := key.(type) {
	case []byte:
		if len(v) == 0 {
			return nil, errors.New("key bytes is empty")
		}
		return jwk.Import(v)

	case string:
		if v == "" {
			return nil, errors.New("key string is empty")
		}
		// 尝试作为 JSON JWK 格式解析
		jwkKey, err := jwk.ParseKey([]byte(v))
		if err == nil {
			return jwkKey, nil
		}
		// 如果不是 JSON 格式，尝试作为原始字节字符串导入
		return jwk.Import([]byte(v))

	case jwk.Key:
		return v, nil

	default:
		// 尝试作为原始密钥类型（RSA、ECDSA、Ed25519 等）
		return jwk.Import(v)
	}
}

// ============= JWT 生成/解析方法 =============

// GenerateJWT 生成并签名 JWT
//
// 参数：
//   - keySet: 签名密钥集合（jwk.Set，会自动选择密钥）
//   - issuerID: 签发者 ID
//   - subject: 主体（sub），可为空
//   - audience: 受众（aud）
//   - expiresIn: 过期时间（秒）
//   - extraClaims: 额外的 claims（可变参数，必须是成对的 key-value，key 必须是 string）
//     示例：GenerateJWT(..., "key1", "value1", "key2", "value2")
//
// 返回：
//   - string: 签名的 JWT 字符串
//   - error: 如果签发失败则返回错误
func GenerateJWT(keySet jwk.Set, issuerID, subject string, audience []string, expiresIn int, extraClaims ...any) (string, error) {
	if keySet == nil {
		return "", errors.New("key set is nil")
	}
	if issuerID == "" {
		return "", errors.New("issuer_id is required")
	}
	if expiresIn <= 0 {
		return "", errors.New("expires_in must be positive")
	}
	if len(extraClaims) > 0 && len(extraClaims)%2 != 0 {
		return "", fmt.Errorf("extraClaims must have even number of arguments for key-value pairs, got %d unmatched arguments", len(extraClaims))
	}

	// 构建 JWT
	now := time.Now()
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)

	tokenBuilder := jwt.NewBuilder().
		JwtID(generateJTI()).
		Issuer(issuerID).
		IssuedAt(now).
		Expiration(expiresAt).
		NotBefore(now)

	if subject != "" {
		tokenBuilder = tokenBuilder.Subject(subject)
	}

	if len(audience) > 0 {
		tokenBuilder = tokenBuilder.Audience(audience)
	}

	// 设置额外的 claims
	for chunk := range slices.Chunk(extraClaims, 2) {
		k, ok := chunk[0].(string)
		if !ok {
			return "", fmt.Errorf("claim key must be string, got %T", chunk[0])
		}
		if k == "" {
			return "", errors.New("claim key cannot be empty")
		}
		tokenBuilder = tokenBuilder.Claim(k, chunk[1])
	}

	token, err := tokenBuilder.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 从 keySet 中选择第一个可用密钥进行签名
	// jwx v3 的 keySet.Keys() 返回 key ID 列表
	keyIDs := keySet.Keys()
	if len(keyIDs) == 0 {
		return "", errors.New("key set is empty")
	}

	// 遍历所有密钥，找到第一个有效的签名密钥
	signingKey, sigAlg, err := findSigningKey(keySet, keyIDs)
	if err != nil {
		return "", err
	}

	// 签名
	signedToken, err := jwt.Sign(token, jwt.WithKey(sigAlg, signingKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signedToken), nil
}

// ExplainJWT 解析并验证 JWT
//
// 参数：
//   - tokenStr: JWT 字符串
//   - keySet: 验证密钥集合（jwk.Set，会自动匹配密钥）
//
// 返回：
//   - jwt.Token: 解析后的 JWT token
//   - error: 如果验证失败则返回错误
func ExplainJWT(tokenStr string, keySet jwk.Set) (jwt.Token, error) {
	if tokenStr == "" {
		return nil, errors.New("token_string is empty")
	}
	if keySet == nil {
		return nil, errors.New("key set is nil")
	}

	token, err := jwt.Parse([]byte(tokenStr),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("explain jwt: %w", err)
	}

	return token, nil
}

// ExtractClaims 解析 JWT 但不验证签名
//
// 参数：
//   - tokenStr: JWT 字符串
//
// 返回：
//   - jwt.Token: 解析后的 JWT token
//   - error: 如果解析失败则返回错误
func ExtractClaims(tokenStr string) (jwt.Token, error) {
	if tokenStr == "" {
		return nil, errors.New("token_string is empty")
	}

	token, err := jwt.Parse([]byte(tokenStr), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}

	return token, nil
}

// generateJTI 生成 JWT ID
func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// findSigningKey 从 keySet 中查找第一个有效的签名密钥
func findSigningKey(keySet jwk.Set, keyIDs []string) (jwk.Key, jwa.SignatureAlgorithm, error) {
	for _, kid := range keyIDs {
		key, ok := keySet.LookupKeyID(kid)
		if !ok {
			continue
		}
		alg, ok := key.Algorithm()
		if !ok {
			continue
		}
		if sigAlg, ok := alg.(jwa.SignatureAlgorithm); ok {
			return key, sigAlg, nil
		}
	}
	return nil, jwa.EmptySignatureAlgorithm(), errors.New("no valid signing key found in key set")
}

// findEncryptionKey 从 keySet 中查找第一个有效的加密密钥
func findEncryptionKey(keySet jwk.Set, keyIDs []string) (jwk.Key, jwa.KeyEncryptionAlgorithm, error) {
	for _, kid := range keyIDs {
		key, ok := keySet.LookupKeyID(kid)
		if !ok {
			continue
		}
		alg, ok := key.Algorithm()
		if !ok {
			continue
		}
		if encAlg, ok := alg.(jwa.KeyEncryptionAlgorithm); ok {
			return key, encAlg, nil
		}
	}
	return nil, jwa.EmptyKeyEncryptionAlgorithm(), errors.New("no valid encryption key found in key set")
}

// ============= JWE 生成/解析方法 =============

// GenerateJWE 生成并加密 JWE
//
// 参数：
//   - plaintext: 明文数据（字节数组）
//   - enc: 内容加密算法（如 jwa.A256GCM()）
//   - keySet: 加密密钥集合（jwk.Set，会自动选择密钥）
//
// 返回：
//   - []byte: 加密后的 JWE 字节数组
//   - error: 如果创建失败则返回错误
func GenerateJWE(plaintext []byte, enc jwa.ContentEncryptionAlgorithm, keySet jwk.Set) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext is empty")
	}
	if keySet == nil {
		return nil, errors.New("key set is nil")
	}

	// 从 keySet 中选择第一个可用的加密密钥
	keyIDs := keySet.Keys()
	if len(keyIDs) == 0 {
		return nil, errors.New("key set is empty")
	}

	// 遍历所有密钥，找到第一个有效的加密密钥
	encryptKey, keyEncAlg, err := findEncryptionKey(keySet, keyIDs)
	if err != nil {
		return nil, err
	}

	encrypted, err := jwe.Encrypt(plaintext,
		jwe.WithKey(keyEncAlg, encryptKey),
		jwe.WithContentEncryption(enc),
	)
	if err != nil {
		return nil, fmt.Errorf("encrypt jwe: %w", err)
	}

	return encrypted, nil
}

// ExplainJWE 解析并解密 JWE
//
// 参数：
//   - jweBytes: JWE 字节数组
//   - keySet: 解密密钥集合（jwk.Set，会自动匹配密钥）
//
// 返回：
//   - []byte: 解密后的明文数据
//   - error: 如果解密失败则返回错误
func ExplainJWE(jweBytes []byte, keySet jwk.Set) ([]byte, error) {
	if len(jweBytes) == 0 {
		return nil, errors.New("jwe_bytes is empty")
	}
	if keySet == nil {
		return nil, errors.New("key set is nil")
	}

	decrypted, err := jwe.Decrypt(jweBytes,
		jwe.WithKeySet(keySet),
	)
	if err != nil {
		return nil, fmt.Errorf("explain jwe: %w", err)
	}

	return decrypted, nil
}
