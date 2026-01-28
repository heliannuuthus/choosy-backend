package token

import (
	"errors"

	pkgtoken "github.com/heliannuuthus/helios/pkg/auth/token"
)

// Token 验证错误
var (
	ErrUnsupportedAudience = errors.New("unsupported audience")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrMissingClaims       = errors.New("missing required claims")
)

// Claims 类型别名（使用 pkg/auth/token 中的定义）
type Claims = pkgtoken.Claims

// AccessToken 类型别名（使用 pkg/auth/token 中的定义）
type AccessToken = pkgtoken.AccessToken
