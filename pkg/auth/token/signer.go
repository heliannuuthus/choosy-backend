package token

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/pkg/auth/utils"
)

// Signer JWT 签名器（绑定特定 id）
type Signer struct {
	id    string
	cache *KeyCache // 只读引用
}

// ID 获取绑定的 id
func (s *Signer) ID() string {
	return s.id
}

// Sign 签发 JWT
//
// 参数：
//   - ctx: 上下文
//   - issuerID: 签发者 ID
//   - subject: 主体（sub），可为空
//   - audience: 受众（aud），可以是 string 或 []string
//   - expiresIn: 过期时间（秒）
//   - extraClaims: 额外的 claims（可变参数，必须是成对的 key-value，key 必须是 string）
//
// 返回：
//   - string: 签名的 JWT 字符串
//   - error: 如果签发失败则返回错误
func (s *Signer) Sign(ctx context.Context, issuerID, subject string, audience interface{}, expiresIn int, extraClaims ...any) (string, error) {
	// 从缓存获取密钥
	entries, err := s.cache.Get(ctx, s.id)
	if err != nil {
		return "", fmt.Errorf("get secrets from cache: %w", err)
	}

	// 构建 keySet
	keySet, err := utils.BuildKeySet(entries)
	if err != nil {
		return "", fmt.Errorf("build key set: %w", err)
	}

	// 转换 audience
	var aud []string
	if audience != nil {
		switch v := audience.(type) {
		case string:
			aud = []string{v}
		case []string:
			aud = v
		default:
			return "", fmt.Errorf("invalid audience type: %T", v)
		}
	}

	// 签发 JWT
	return utils.GenerateJWT(keySet, issuerID, subject, aud, expiresIn, extraClaims...)
}
