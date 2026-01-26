package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Store 会话、授权码和 RefreshToken 存储接口
type Store interface {
	// Session 管理
	SaveSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	UpdateSession(ctx context.Context, session *Session) error
	DeleteSession(ctx context.Context, sessionID string) error

	// AuthorizationCode 管理
	SaveAuthCode(ctx context.Context, code *AuthorizationCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthorizationCode, error)
	MarkAuthCodeUsed(ctx context.Context, code string) error
	DeleteAuthCode(ctx context.Context, code string) error

	// RefreshToken 管理
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RevokeUserRefreshTokens(ctx context.Context, userID string) error
	ListUserRefreshTokens(ctx context.Context, userID, clientID string) ([]*RefreshToken, error)
}

// RefreshToken 刷新令牌（存储在 Redis）
type RefreshToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"` // 实际存储的是用户的 OpenID
	ClientID  string    `json:"client_id"`
	Audience  string    `json:"audience"` // 目标服务 ID
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

// IsValid 检查是否有效
func (r *RefreshToken) IsValid() bool {
	return !r.Revoked && time.Now().Before(r.ExpiresAt)
}

// GenerateRefreshTokenValue 生成刷新令牌值
func GenerateRefreshTokenValue() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// 错误定义
var (
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionExpired       = errors.New("session expired")
	ErrCodeNotFound         = errors.New("authorization code not found")
	ErrCodeExpired          = errors.New("authorization code expired")
	ErrCodeUsed             = errors.New("authorization code already used")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrRefreshTokenRevoked  = errors.New("refresh token revoked")
)

// MemoryStore 内存存储（开发/测试用）
type MemoryStore struct {
	mu            sync.RWMutex
	sessions      map[string]*Session
	codes         map[string]*AuthorizationCode
	refreshTokens map[string]*RefreshToken
	userTokens    map[string][]string // userID -> []token
}

// NewMemoryStore 创建内存存储
func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		sessions:      make(map[string]*Session),
		codes:         make(map[string]*AuthorizationCode),
		refreshTokens: make(map[string]*RefreshToken),
		userTokens:    make(map[string][]string),
	}
	go store.cleanupLoop()
	return store
}

func (s *MemoryStore) SaveSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemoryStore) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	return session, nil
}

func (s *MemoryStore) UpdateSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemoryStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

func (s *MemoryStore) SaveAuthCode(ctx context.Context, code *AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.Code] = code
	return nil
}

func (s *MemoryStore) GetAuthCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	authCode, ok := s.codes[code]
	if !ok {
		return nil, ErrCodeNotFound
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrCodeExpired
	}
	if authCode.Used {
		return nil, ErrCodeUsed
	}
	return authCode, nil
}

func (s *MemoryStore) MarkAuthCodeUsed(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	authCode, ok := s.codes[code]
	if !ok {
		return ErrCodeNotFound
	}
	authCode.Used = true
	return nil
}

func (s *MemoryStore) DeleteAuthCode(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, code)
	return nil
}

func (s *MemoryStore) SaveRefreshToken(ctx context.Context, token *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token.Token] = token
	s.userTokens[token.UserID] = append(s.userTokens[token.UserID], token.Token)
	return nil
}

func (s *MemoryStore) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rt, ok := s.refreshTokens[token]
	if !ok {
		return nil, ErrRefreshTokenNotFound
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}
	if rt.Revoked {
		return nil, ErrRefreshTokenRevoked
	}
	return rt, nil
}

func (s *MemoryStore) RevokeRefreshToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rt, ok := s.refreshTokens[token]; ok {
		rt.Revoked = true
	}
	return nil
}

func (s *MemoryStore) RevokeUserRefreshTokens(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tokens, ok := s.userTokens[userID]; ok {
		for _, token := range tokens {
			if rt, exists := s.refreshTokens[token]; exists {
				rt.Revoked = true
			}
		}
	}
	return nil
}

func (s *MemoryStore) ListUserRefreshTokens(ctx context.Context, userID, clientID string) ([]*RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*RefreshToken
	if tokens, ok := s.userTokens[userID]; ok {
		for _, token := range tokens {
			if rt, exists := s.refreshTokens[token]; exists {
				if clientID == "" || rt.ClientID == clientID {
					if !rt.Revoked && time.Now().Before(rt.ExpiresAt) {
						result = append(result, rt)
					}
				}
			}
		}
	}
	return result, nil
}

func (s *MemoryStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.cleanup()
	}
}

func (s *MemoryStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	for code, authCode := range s.codes {
		if now.After(authCode.ExpiresAt) {
			delete(s.codes, code)
		}
	}
	for token, rt := range s.refreshTokens {
		if now.After(rt.ExpiresAt) {
			delete(s.refreshTokens, token)
		}
	}
}

// RedisStore Redis 存储
type RedisStore struct {
	client             RedisClient
	sessionPrefix      string
	codePrefix         string
	refreshTokenPrefix string
	userTokenPrefix    string
	sessionTTL         time.Duration
	codeTTL            time.Duration
}

// RedisClient Redis 客户端接口
type RedisClient interface {
	Set(ctx context.Context, key string, value any, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Del(ctx context.Context, keys ...string) error
	SAdd(ctx context.Context, key string, members ...any) error
	SMembers(ctx context.Context, key string) ([]string, error)
}

// RedisStoreConfig Redis 存储配置
type RedisStoreConfig struct {
	Client             RedisClient
	SessionPrefix      string
	CodePrefix         string
	RefreshTokenPrefix string
	UserTokenPrefix    string
	SessionTTL         time.Duration
	CodeTTL            time.Duration
}

// NewRedisStore 创建 Redis 存储
func NewRedisStore(cfg *RedisStoreConfig) *RedisStore {
	sessionPrefix := cfg.SessionPrefix
	if sessionPrefix == "" {
		sessionPrefix = "auth:session:"
	}
	codePrefix := cfg.CodePrefix
	if codePrefix == "" {
		codePrefix = "auth:code:"
	}
	refreshTokenPrefix := cfg.RefreshTokenPrefix
	if refreshTokenPrefix == "" {
		refreshTokenPrefix = "auth:rt:"
	}
	userTokenPrefix := cfg.UserTokenPrefix
	if userTokenPrefix == "" {
		userTokenPrefix = "auth:user:rt:"
	}
	sessionTTL := cfg.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = 10 * time.Minute
	}
	codeTTL := cfg.CodeTTL
	if codeTTL == 0 {
		codeTTL = 5 * time.Minute
	}
	return &RedisStore{
		client:             cfg.Client,
		sessionPrefix:      sessionPrefix,
		codePrefix:         codePrefix,
		refreshTokenPrefix: refreshTokenPrefix,
		userTokenPrefix:    userTokenPrefix,
		sessionTTL:         sessionTTL,
		codeTTL:            codeTTL,
	}
}

func (s *RedisStore) SaveSession(ctx context.Context, session *Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.sessionPrefix+session.ID, string(data), s.sessionTTL)
}

func (s *RedisStore) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	data, err := s.client.Get(ctx, s.sessionPrefix+sessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	var session Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	return &session, nil
}

func (s *RedisStore) UpdateSession(ctx context.Context, session *Session) error {
	return s.SaveSession(ctx, session)
}

func (s *RedisStore) DeleteSession(ctx context.Context, sessionID string) error {
	return s.client.Del(ctx, s.sessionPrefix+sessionID)
}

func (s *RedisStore) SaveAuthCode(ctx context.Context, code *AuthorizationCode) error {
	data, err := json.Marshal(code)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.codePrefix+code.Code, string(data), s.codeTTL)
}

func (s *RedisStore) GetAuthCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	data, err := s.client.Get(ctx, s.codePrefix+code)
	if err != nil {
		return nil, ErrCodeNotFound
	}
	var authCode AuthorizationCode
	if err := json.Unmarshal([]byte(data), &authCode); err != nil {
		return nil, err
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrCodeExpired
	}
	if authCode.Used {
		return nil, ErrCodeUsed
	}
	return &authCode, nil
}

func (s *RedisStore) MarkAuthCodeUsed(ctx context.Context, code string) error {
	authCode, err := s.GetAuthCode(ctx, code)
	if err != nil {
		return err
	}
	authCode.Used = true
	data, _ := json.Marshal(authCode)
	remaining := time.Until(authCode.ExpiresAt)
	if remaining < 0 {
		remaining = time.Second
	}
	return s.client.Set(ctx, s.codePrefix+code, string(data), remaining)
}

func (s *RedisStore) DeleteAuthCode(ctx context.Context, code string) error {
	return s.client.Del(ctx, s.codePrefix+code)
}

func (s *RedisStore) SaveRefreshToken(ctx context.Context, token *RefreshToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	ttl := time.Until(token.ExpiresAt)
	if ttl < 0 {
		ttl = time.Second
	}
	if err := s.client.Set(ctx, s.refreshTokenPrefix+token.Token, string(data), ttl); err != nil {
		return err
	}
	return s.client.SAdd(ctx, s.userTokenPrefix+token.UserID, token.Token)
}

func (s *RedisStore) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	data, err := s.client.Get(ctx, s.refreshTokenPrefix+token)
	if err != nil {
		return nil, ErrRefreshTokenNotFound
	}
	var rt RefreshToken
	if err := json.Unmarshal([]byte(data), &rt); err != nil {
		return nil, err
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}
	if rt.Revoked {
		return nil, ErrRefreshTokenRevoked
	}
	return &rt, nil
}

func (s *RedisStore) RevokeRefreshToken(ctx context.Context, token string) error {
	data, err := s.client.Get(ctx, s.refreshTokenPrefix+token)
	if err != nil {
		return nil
	}
	var rt RefreshToken
	if err := json.Unmarshal([]byte(data), &rt); err != nil {
		return err
	}
	rt.Revoked = true
	newData, _ := json.Marshal(rt)
	remaining := time.Until(rt.ExpiresAt)
	if remaining < 0 {
		remaining = time.Second
	}
	return s.client.Set(ctx, s.refreshTokenPrefix+token, string(newData), remaining)
}

func (s *RedisStore) RevokeUserRefreshTokens(ctx context.Context, userID string) error {
	tokens, err := s.client.SMembers(ctx, s.userTokenPrefix+userID)
	if err != nil {
		return nil
	}
	for _, token := range tokens {
		_ = s.RevokeRefreshToken(ctx, token)
	}
	return nil
}

func (s *RedisStore) ListUserRefreshTokens(ctx context.Context, userID, clientID string) ([]*RefreshToken, error) {
	tokens, err := s.client.SMembers(ctx, s.userTokenPrefix+userID)
	if err != nil {
		return nil, nil
	}
	var result []*RefreshToken
	for _, token := range tokens {
		rt, err := s.GetRefreshToken(ctx, token)
		if err != nil {
			continue
		}
		if clientID == "" || rt.ClientID == clientID {
			result = append(result, rt)
		}
	}
	return result, nil
}
