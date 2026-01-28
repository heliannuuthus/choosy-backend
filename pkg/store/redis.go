package store

import (
	"context"
	"time"
)

// RedisClient Redis 客户端接口
// 通用的 Redis 操作接口，可被各模块复用
type RedisClient interface {
	// 基础操作
	Set(ctx context.Context, key string, value any, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Del(ctx context.Context, keys ...string) error

	// Set 操作
	SAdd(ctx context.Context, key string, members ...any) error
	SMembers(ctx context.Context, key string) ([]string, error)

	// Hash 操作
	HSet(ctx context.Context, key string, values ...any) error
	HGet(ctx context.Context, key, field string) (string, error)
	HGetAll(ctx context.Context, key string) (map[string]string, error)
	HDel(ctx context.Context, key string, fields ...string) error

	// 过期时间
	Expire(ctx context.Context, key string, expiration time.Duration) error
	TTL(ctx context.Context, key string) (time.Duration, error)

	// 检查存在
	Exists(ctx context.Context, keys ...string) (int64, error)
}
