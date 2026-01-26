package config

import "time"

// HermesCacheConfig Hermes 缓存配置
type HermesCacheConfig struct {
	MaxSize     int64         `mapstructure:"max-size"`     // 最大缓存条目数
	NumCounters int64         `mapstructure:"num-counters"` // 计数器数量
	BufferItems int64         `mapstructure:"buffer-items"` // 缓冲区大小
	TTL         time.Duration `mapstructure:"ttl"`          // 缓存过期时间
}

// 默认值
const (
	defaultHermesCacheMaxSize     = 1000
	defaultHermesCacheNumCounters = 10000
	defaultHermesCacheBufferItems = 64
	defaultHermesCacheTTL         = 2 * time.Minute
)

// GetHermesCacheConfig 获取 Hermes 缓存配置
func GetHermesCacheConfig() *HermesCacheConfig {
	cfg := &HermesCacheConfig{
		MaxSize:     defaultHermesCacheMaxSize,
		NumCounters: defaultHermesCacheNumCounters,
		BufferItems: defaultHermesCacheBufferItems,
		TTL:         defaultHermesCacheTTL,
	}

	v := V()

	if maxSize := v.GetInt64("hermes.cache.max-size"); maxSize > 0 {
		cfg.MaxSize = maxSize
	}
	if numCounters := v.GetInt64("hermes.cache.num-counters"); numCounters > 0 {
		cfg.NumCounters = numCounters
	}
	if bufferItems := v.GetInt64("hermes.cache.buffer-items"); bufferItems > 0 {
		cfg.BufferItems = bufferItems
	}
	if ttl := v.GetDuration("hermes.cache.ttl"); ttl > 0 {
		cfg.TTL = ttl
	}

	return cfg
}
