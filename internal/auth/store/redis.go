package store

import (
	"context"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
	pkgstore "github.com/heliannuuthus/helios/pkg/store"
)

// RedisStore Redis 存储
type RedisStore struct {
	client             pkgstore.RedisClient
	sessionPrefix      string
	codePrefix         string
	refreshTokenPrefix string
	userTokenPrefix    string
	sessionTTL         time.Duration
	codeTTL            time.Duration
}

// RedisStoreConfig Redis 存储配置
type RedisStoreConfig struct {
	Client             pkgstore.RedisClient
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
	data, err := json.Marshal(authCode)
	if err != nil {
		return fmt.Errorf("marshal auth code: %w", err)
	}
	remaining := time.Until(authCode.ExpiresAt)
	if remaining < 0 {
		remaining = time.Second
	}
	return s.client.Set(ctx, s.codePrefix+authCode.Code, string(data), remaining)
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
	newData, err := json.Marshal(rt)
	if err != nil {
		return fmt.Errorf("marshal refresh token: %w", err)
	}
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
		if err := s.RevokeRefreshToken(ctx, token); err != nil {
			logger.Warnf("[RedisStore] revoke refresh token failed: %v", err)
		}
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
