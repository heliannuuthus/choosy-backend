package token

import (
	"context"
	"errors"
	"fmt"

	"github.com/heliannuuthus/helios/pkg/auth/utils"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Verifier JWT 验证器（绑定特定 id，即当前服务的标识）
type Verifier struct {
	id    string
	cache *KeyCache
}

// ID 获取绑定的 id
func (v *Verifier) ID() string {
	return v.id
}

// Validate 验证 JWT 并返回 AccessToken
func (v *Verifier) Validate(ctx context.Context, tokenStr string) (*AccessToken, error) {
	token, err := utils.ExtractClaims(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}

	aud, _ := token.Audience()
	if !containsAudience(aud, v.id) {
		return nil, errors.New("audience mismatch")
	}

	var cli string
	if err := token.Get("cli", &cli); err != nil {
		return nil, errors.New("cli claim not found")
	}
	if cli == "" {
		return nil, errors.New("cli claim is empty")
	}

	callerEntries, err := v.cache.Get(ctx, cli)
	if err != nil {
		return nil, fmt.Errorf("get caller secrets: %w", err)
	}

	callerKeySet, err := utils.BuildKeySet(callerEntries)
	if err != nil {
		return nil, fmt.Errorf("build caller key set: %w", err)
	}

	verifiedToken, err := utils.ExplainJWT(tokenStr, callerKeySet)
	if err != nil {
		return nil, fmt.Errorf("explain jwt signature: %w", err)
	}

	return NewAccessToken(verifiedToken), nil
}

// Verify 简单验证 JWT
func (v *Verifier) Verify(ctx context.Context, tokenStr string) (jwt.Token, error) {
	entries, err := v.cache.Get(ctx, v.id)
	if err != nil {
		return nil, fmt.Errorf("get secrets from cache: %w", err)
	}

	keySet, err := utils.BuildKeySet(entries)
	if err != nil {
		return nil, fmt.Errorf("build key set: %w", err)
	}

	return utils.ExplainJWT(tokenStr, keySet)
}

func containsAudience(audience []string, target string) bool {
	for _, aud := range audience {
		if aud == target {
			return true
		}
	}
	return false
}
