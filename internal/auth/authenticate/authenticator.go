package authenticate

import (
	"context"
)

// Authenticator 认证器接口
type Authenticator interface {
	// Type 返回认证器类型
	Type() AuthType

	// Supports 判断是否支持该 connection
	Supports(connection string) bool

	// Authenticate 执行认证
	Authenticate(ctx context.Context, connection string, data map[string]any) (*AuthResult, error)
}
