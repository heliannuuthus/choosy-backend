package token

import (
	"context"
	"sync"
	"time"

	"github.com/heliannuuthus/helios/pkg/auth/secret"
)

// Manager 认证管理器（全局管理者）
// 持有 KeyCache，统管 Signer/Verifier/Encryptor/Decryptor
type Manager struct {
	cache *KeyCache

	// 组件缓存（同一 clientID 复用同一实例）
	signers    sync.Map // clientID -> *Signer
	verifiers  sync.Map // clientID -> *Verifier
	encryptors sync.Map // clientID -> *Encryptor
	decryptors sync.Map // clientID -> *Decryptor
}

// ManagerOption Manager 配置选项
type ManagerOption func(*managerOptions)

type managerOptions struct {
	ttl           time.Duration
	refreshBefore time.Duration
}

// WithTTL 设置缓存 TTL
func WithTTL(ttl time.Duration) ManagerOption {
	return func(o *managerOptions) {
		o.ttl = ttl
	}
}

// WithRefreshBefore 设置提前刷新时间
func WithRefreshBefore(d time.Duration) ManagerOption {
	return func(o *managerOptions) {
		o.refreshBefore = d
	}
}

// NewManager 创建 Manager
func NewManager(loader secret.Loader, opts ...ManagerOption) *Manager {
	options := &managerOptions{
		ttl:           5 * time.Minute,
		refreshBefore: 1 * time.Minute,
	}

	for _, opt := range opts {
		opt(options)
	}

	return &Manager{
		cache: NewKeyCache(loader, options.ttl, options.refreshBefore),
	}
}

// Start 启动 Manager（启动后台刷新）
func (m *Manager) Start(ctx context.Context) {
	m.cache.Start(ctx)
}

// Cache 获取底层 KeyCache（用于高级操作）
func (m *Manager) Cache() *KeyCache {
	return m.cache
}

// Signer 获取 Signer（首次创建，之后复用）
func (m *Manager) Signer(id string) *Signer {
	if v, ok := m.signers.Load(id); ok {
		return v.(*Signer)
	}

	signer := &Signer{
		id:    id,
		cache: m.cache,
	}

	// 使用 LoadOrStore 避免竞态条件
	if v, loaded := m.signers.LoadOrStore(id, signer); loaded {
		return v.(*Signer)
	}

	return signer
}

// Verifier 获取 Verifier（首次创建，之后复用）
func (m *Manager) Verifier(id string) *Verifier {
	if v, ok := m.verifiers.Load(id); ok {
		return v.(*Verifier)
	}

	verifier := &Verifier{
		id:    id,
		cache: m.cache,
	}

	if v, loaded := m.verifiers.LoadOrStore(id, verifier); loaded {
		return v.(*Verifier)
	}

	return verifier
}

// Encryptor 获取 Encryptor（首次创建，之后复用）
func (m *Manager) Encryptor(id string) *Encryptor {
	if v, ok := m.encryptors.Load(id); ok {
		return v.(*Encryptor)
	}

	encryptor := &Encryptor{
		id:    id,
		cache: m.cache,
	}

	if v, loaded := m.encryptors.LoadOrStore(id, encryptor); loaded {
		return v.(*Encryptor)
	}

	return encryptor
}

// Decryptor 获取 Decryptor（首次创建，之后复用）
func (m *Manager) Decryptor(id string) *Decryptor {
	if v, ok := m.decryptors.Load(id); ok {
		return v.(*Decryptor)
	}

	decryptor := &Decryptor{
		id:    id,
		cache: m.cache,
	}

	if v, loaded := m.decryptors.LoadOrStore(id, decryptor); loaded {
		return v.(*Decryptor)
	}

	return decryptor
}
