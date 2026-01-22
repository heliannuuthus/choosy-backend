package token

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/pkg/auth/utils"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

// Encryptor JWE 加密器（绑定特定 id）
type Encryptor struct {
	id    string
	cache *KeyCache // 只读引用
}

// ID 获取绑定的 id
func (e *Encryptor) ID() string {
	return e.id
}

// Encrypt 加密数据为 JWE
//
// 参数：
//   - ctx: 上下文
//   - plaintext: 明文数据
//   - enc: 内容加密算法
//
// 返回：
//   - []byte: 加密后的 JWE 字节数组
//   - error: 如果加密失败则返回错误
func (e *Encryptor) Encrypt(ctx context.Context, plaintext []byte, enc jwa.ContentEncryptionAlgorithm) ([]byte, error) {
	// 从缓存获取密钥
	entries, err := e.cache.Get(ctx, e.id)
	if err != nil {
		return nil, fmt.Errorf("get secrets from cache: %w", err)
	}

	// 构建 keySet
	keySet, err := utils.BuildKeySet(entries)
	if err != nil {
		return nil, fmt.Errorf("build key set: %w", err)
	}

	return utils.GenerateJWE(plaintext, enc, keySet)
}
