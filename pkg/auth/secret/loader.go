package secret

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SecretEntry 密钥条目
type SecretEntry struct {
	ID        string    // 密钥 ID
	Value     []byte    // 密钥值
	CreatedAt time.Time // 创建时间
	ExpiresAt time.Time // 过期时间（零值表示永不过期）
}

// IsExpired 检查密钥是否已过期
func (e *SecretEntry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.ExpiresAt)
}

// GetValue 返回密钥值（实现 utils.BuildKeySet 所需接口）
func (e *SecretEntry) GetValue() []byte {
	return e.Value
}

// Loader 密钥加载器接口
type Loader interface {
	Load(ctx context.Context, id string) ([]*SecretEntry, error)
}

// LoaderFunc 函数适配器
type LoaderFunc func(ctx context.Context, clientID string) ([]*SecretEntry, error)

func (f LoaderFunc) Load(ctx context.Context, clientID string) ([]*SecretEntry, error) {
	return f(ctx, clientID)
}

// Store 并发安全的密钥存储
type Store struct {
	mu      sync.RWMutex
	secrets map[string][]*SecretEntry // clientID -> 有序密钥列表
}

// NewStore 创建密钥存储
func NewStore() *Store {
	return &Store{
		secrets: make(map[string][]*SecretEntry),
	}
}

// Register 注册客户端密钥
func (s *Store) Register(clientID string, secrets ...[]byte) error {
	if clientID == "" {
		return errors.New("client_id is required")
	}
	if len(secrets) == 0 {
		return errors.New("at least one secret is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries := make([]*SecretEntry, len(secrets))
	now := time.Now()
	for i, secret := range secrets {
		if len(secret) == 0 {
			return fmt.Errorf("secret[%d] is empty", i)
		}
		entries[i] = &SecretEntry{
			ID:        fmt.Sprintf("%s-%d", clientID, i),
			Value:     secret,
			CreatedAt: now,
		}
	}

	s.secrets[clientID] = entries
	return nil
}

// Load 实现 Loader 接口
func (s *Store) Load(ctx context.Context, clientID string) ([]*SecretEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, ok := s.secrets[clientID]
	if !ok {
		return nil, fmt.Errorf("client %s not found", clientID)
	}

	// 返回有效密钥
	result := make([]*SecretEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsExpired() {
			result = append(result, e)
		}
	}

	if len(result) == 0 {
		return nil, errors.New("no valid secret found")
	}

	return result, nil
}

// Rotate 轮换密钥（新密钥成为第一个）
func (s *Store) Rotate(clientID string, secret []byte) error {
	if len(secret) == 0 {
		return errors.New("secret is empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := &SecretEntry{
		ID:        fmt.Sprintf("%s-%d", clientID, time.Now().UnixNano()),
		Value:     secret,
		CreatedAt: time.Now(),
	}

	entries := s.secrets[clientID]
	s.secrets[clientID] = append([]*SecretEntry{entry}, entries...)
	return nil
}

// Current 获取当前使用的密钥
func (s *Store) Current(clientID string) (*SecretEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, ok := s.secrets[clientID]
	if !ok {
		return nil, fmt.Errorf("client %s not found", clientID)
	}

	for _, e := range entries {
		if !e.IsExpired() {
			return e, nil
		}
	}

	return nil, errors.New("no valid secret found")
}
