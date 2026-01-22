package token

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/pkg/auth/utils"
)

// Decryptor JWE 解密器（绑定特定 id）
type Decryptor struct {
	id    string
	cache *KeyCache // 只读引用
}

// ID 获取绑定的 id
func (d *Decryptor) ID() string {
	return d.id
}

// Decrypt 解密 JWE
//
// 参数：
//   - ctx: 上下文
//   - jweBytes: JWE 字节数组
//
// 返回：
//   - []byte: 解密后的明文数据
//   - error: 如果解密失败则返回错误
func (d *Decryptor) Decrypt(ctx context.Context, jweBytes []byte) ([]byte, error) {
	// 从缓存获取密钥
	entries, err := d.cache.Get(ctx, d.id)
	if err != nil {
		return nil, fmt.Errorf("get secrets from cache: %w", err)
	}

	// 构建 keySet
	keySet, err := utils.BuildKeySet(entries)
	if err != nil {
		return nil, fmt.Errorf("build key set: %w", err)
	}

	return utils.ExplainJWE(jweBytes, keySet)
}
