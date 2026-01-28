package authenticate

import (
	"context"
	"errors"
	"fmt"

	"github.com/heliannuuthus/helios/internal/auth/idp"
)

// IDPAuthenticator IDP 认证器
type IDPAuthenticator struct {
	registry *idp.Registry
}

// NewIDPAuthenticator 创建 IDP 认证器
func NewIDPAuthenticator(registry *idp.Registry) *IDPAuthenticator {
	return &IDPAuthenticator{
		registry: registry,
	}
}

// Type 返回认证器类型
func (*IDPAuthenticator) Type() AuthType {
	return AuthTypeIDP
}

// Supports 判断是否支持该 connection
func (a *IDPAuthenticator) Supports(connection string) bool {
	return a.registry.Has(connection)
}

// Authenticate 执行认证
func (a *IDPAuthenticator) Authenticate(ctx context.Context, connection string, data map[string]any) (*AuthResult, error) {
	provider, ok := a.registry.Get(connection)
	if !ok {
		return nil, fmt.Errorf("unsupported idp: %s", connection)
	}

	// 获取 code
	code, ok := data["code"].(string)
	if !ok || code == "" {
		return nil, errors.New("code is required")
	}

	// 调用 IDP Exchange
	result, err := provider.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("idp exchange failed: %w", err)
	}

	return &AuthResult{
		ProviderID: result.ProviderID,
		UnionID:    result.UnionID,
		RawData:    result.RawData,
	}, nil
}
