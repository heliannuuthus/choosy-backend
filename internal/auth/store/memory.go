package store

import (
	"context"
	"sync"
	"time"
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

func (s *MemoryStore) SaveSession(_ context.Context, session *Session) error {
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

func (s *MemoryStore) UpdateSession(_ context.Context, session *Session) error {
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
