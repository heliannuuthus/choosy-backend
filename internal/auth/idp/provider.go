package idp

import (
	"context"
	"sync"
)

// Provider IDP 提供者接口
type Provider interface {
	// Type 返回 IDP 类型标识
	Type() string

	// Exchange 用 code 换取用户信息
	Exchange(ctx context.Context, code string) (*ExchangeResult, error)

	// GetPhoneNumber 获取手机号（可选功能）
	GetPhoneNumber(ctx context.Context, code string) (string, error)
}

// ExchangeResult 换取结果
type ExchangeResult struct {
	ProviderID string // IDP 侧用户唯一标识（openid）
	UnionID    string // 联合 ID（可选）
	RawData    string // 原始响应 JSON
}

// Registry Provider 注册表
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry 创建注册表
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

// Register 注册 Provider
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Type()] = p
}

// Get 获取 Provider
func (r *Registry) Get(idpType string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[idpType]
	return p, ok
}

// List 列出所有已注册的 IDP 类型
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.providers))
	for t := range r.providers {
		types = append(types, t)
	}
	return types
}

// Has 检查是否已注册指定类型的 Provider
func (r *Registry) Has(idpType string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.providers[idpType]
	return ok
}
