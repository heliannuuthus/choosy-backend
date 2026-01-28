package utils

import (
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// UserClaims 用户信息结构（用于加密/解密 sub）
type UserClaims struct {
	OpenID   string `json:"openid,omitempty"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

// DecryptUserClaims 使用指定密钥解密用户信息
func DecryptUserClaims(encryptedSub string, decryptKey jwk.Key) (*UserClaims, error) {
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

	var claims UserClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// EncryptUserClaims 加密用户信息为 JWE
func EncryptUserClaims(claims *UserClaims, encryptKey jwk.Key) (string, error) {
	plaintext, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encrypted, err := jwe.Encrypt(plaintext,
		jwe.WithKey(jwa.DIRECT(), encryptKey),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", err
	}

	return string(encrypted), nil
}
