package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Session 认证会话
type Session struct {
	ID                  string    `json:"id"`
	ClientID            string    `json:"client_id"`
	Audience            string    `json:"audience"` // 目标服务 ID
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	State               string    `json:"state"`
	Scope               string    `json:"scope"`
	Connection          string    `json:"connection,omitempty"` // 用户选择的 connection
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`

	// 登录后填充
	UserID       string `json:"user_id,omitempty"`
	IDP          string `json:"idp,omitempty"`
	GrantedScope string `json:"granted_scope,omitempty"` // 实际授予的 scope
}

// AuthorizationCode 授权码
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	Audience            string    `json:"audience"` // 目标服务 ID
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	Scope               string    `json:"scope"` // 实际授予的 scope
	UserID              string    `json:"user_id"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used"`
}

// RefreshToken 刷新令牌
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

// GenerateRefreshTokenValue 生成刷新令牌值
func GenerateRefreshTokenValue() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate refresh token value failed: %v", err))
	}
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
