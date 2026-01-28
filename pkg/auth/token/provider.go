package token

import (
	"context"
	"sync"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// KeyProvider 密钥提供者接口
type KeyProvider interface {
	Get(ctx context.Context, keyID string) (jwk.Key, error)
}

// KeyProviderFunc 函数式 KeyProvider
type KeyProviderFunc func(ctx context.Context, keyID string) (jwk.Key, error)

// Get 实现 KeyProvider 接口
func (f KeyProviderFunc) Get(ctx context.Context, keyID string) (jwk.Key, error) {
	return f(ctx, keyID)
}

// JWKSKeyProvider 基于 JWKS 的公钥提供者
// 使用 jwk.Cache 自动刷新，遵循 HTTP Cache-Control
type JWKSKeyProvider struct {
	cache        *jwk.Cache
	endpointFunc func() string // 动态获取 endpoint
	mu           sync.RWMutex
	registered   map[string]bool
}

// NewJWKSKeyProvider 创建 JWKS 公钥提供者
// endpointFunc: 动态获取 Auth 服务端点的函数（支持热更新）
func NewJWKSKeyProvider(ctx context.Context, endpointFunc func() string) (*JWKSKeyProvider, error) {
	cache, err := jwk.NewCache(ctx, httprc.NewClient(httprc.WithWhitelist(httprc.NewInsecureWhitelist())))
	if err != nil {
		return nil, err
	}

	return &JWKSKeyProvider{
		cache:        cache,
		endpointFunc: endpointFunc,
		registered:   make(map[string]bool),
	}, nil
}

// Get 获取公钥
// URL 固定为: {endpoint}/pubkeys?client_id={clientID}
func (p *JWKSKeyProvider) Get(ctx context.Context, clientID string) (jwk.Key, error) {
	// 1. 构建 JWKS URL（路径固定）
	url := p.endpointFunc() + "/pubkeys?client_id=" + clientID

	// 2. 动态注册（如未注册）
	p.mu.RLock()
	registered := p.registered[url]
	p.mu.RUnlock()

	if !registered {
		p.mu.Lock()
		if !p.registered[url] {
			if err := p.cache.Register(ctx, url); err != nil {
				p.mu.Unlock()
				return nil, err
			}
			p.registered[url] = true
		}
		p.mu.Unlock()
	}

	// 3. 从缓存获取
	set, err := p.cache.Lookup(ctx, url)
	if err != nil {
		return nil, err
	}

	key, ok := set.Key(0)
	if !ok {
		return nil, ErrNoKeysInJWKS
	}

	return key, nil
}
