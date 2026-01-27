package cache

import (
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Manager 缓存管理器，为每个类型管理独立的 cache
// 配置从全局 viper 动态读取，支持热更新
// 每个 cache 类型都有独立的配置前缀：auth.cache.{type}.{config-key}
type Manager struct {
	domainCache                     *ristretto.Cache[string, *models.DomainWithKey]
	applicationCache                *ristretto.Cache[string, *models.ApplicationWithKey]
	serviceCache                    *ristretto.Cache[string, *models.ServiceWithKey]
	applicationServiceRelationCache *ristretto.Cache[string, []models.ApplicationServiceRelation]
	relationshipCache               *ristretto.Cache[string, []models.Relationship]
}

// getCacheConfig 从全局 viper 获取指定 cache 类型的配置
func getCacheConfig(cacheType string) (maxCost int64, numCounters int64, bufferItems int64) {
	v := config.V()
	prefix := "auth.cache." + cacheType + "."

	// 默认值
	defaultMaxCost := int64(1000)
	defaultNumCounters := int64(10000)
	defaultBufferItems := int64(64)

	// 从配置读取，如果没有则使用默认值
	if val := v.GetInt64(prefix + "cache-size"); val > 0 {
		maxCost = val
	} else {
		maxCost = defaultMaxCost
	}

	if val := v.GetInt64(prefix + "num-counters"); val > 0 {
		numCounters = val
	} else {
		numCounters = defaultNumCounters
	}

	if val := v.GetInt64(prefix + "buffer-items"); val > 0 {
		bufferItems = val
	} else {
		bufferItems = defaultBufferItems
	}

	return maxCost, numCounters, bufferItems
}

// GetTTL 从全局 viper 获取指定 cache 类型的 TTL
func GetTTL(cacheType string) time.Duration {
	v := config.V()
	prefix := "auth.cache." + cacheType + "."
	defaultTTL := 2 * time.Minute

	if ttl := v.GetDuration(prefix + "ttl"); ttl > 0 {
		return ttl
	}
	return defaultTTL
}

// GetKeyPrefix 从全局 viper 获取指定 cache 类型的 key 前缀
func GetKeyPrefix(cacheType string) string {
	v := config.V()
	prefix := "auth.cache." + cacheType + "."

	// 默认前缀映射
	defaultPrefixes := map[string]string{
		"domain":                       "domain:",
		"application":                  "app:",
		"service":                      "svc:",
		"user":                         "user:",
		"application-service-relation": "app-svc-rel:",
		"relationship":                 "rel:",
	}

	if keyPrefix := v.GetString(prefix + "key-prefix"); keyPrefix != "" {
		return keyPrefix
	}

	// 如果配置中没有，返回默认值
	if defaultPrefix, ok := defaultPrefixes[cacheType]; ok {
		return defaultPrefix
	}

	// 最后的降级方案
	return cacheType + ":"
}

// NewManager 创建缓存管理器
// 所有配置都从全局 viper 读取，支持热更新
func NewManager() *Manager {
	cm := &Manager{}

	// 创建 Domain cache
	maxCost, numCounters, bufferItems := getCacheConfig("domain")
	domainCache, err := ristretto.NewCache(&ristretto.Config[string, *models.DomainWithKey]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[CacheManager] 创建 Domain 缓存失败: %v", err)
	} else {
		cm.domainCache = domainCache
	}

	// 创建 Application cache
	maxCost, numCounters, bufferItems = getCacheConfig("application")
	applicationCache, err := ristretto.NewCache(&ristretto.Config[string, *models.ApplicationWithKey]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[CacheManager] 创建 Application 缓存失败: %v", err)
	} else {
		cm.applicationCache = applicationCache
	}

	// 创建 Service cache
	maxCost, numCounters, bufferItems = getCacheConfig("service")
	serviceCache, err := ristretto.NewCache(&ristretto.Config[string, *models.ServiceWithKey]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[CacheManager] 创建 Service 缓存失败: %v", err)
	} else {
		cm.serviceCache = serviceCache
	}

	// 创建 ApplicationServiceRelation cache
	maxCost, numCounters, bufferItems = getCacheConfig("application-service-relation")
	applicationServiceRelationCache, err := ristretto.NewCache(&ristretto.Config[string, []models.ApplicationServiceRelation]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[CacheManager] 创建 ApplicationServiceRelation 缓存失败: %v", err)
	} else {
		cm.applicationServiceRelationCache = applicationServiceRelationCache
	}

	// 创建 Relationship cache
	maxCost, numCounters, bufferItems = getCacheConfig("relationship")
	relationshipCache, err := ristretto.NewCache(&ristretto.Config[string, []models.Relationship]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[CacheManager] 创建 Relationship 缓存失败: %v", err)
	} else {
		cm.relationshipCache = relationshipCache
	}

	return cm
}

// Close 关闭所有缓存
func (cm *Manager) Close() {
	if cm.domainCache != nil {
		cm.domainCache.Close()
	}
	if cm.applicationCache != nil {
		cm.applicationCache.Close()
	}
	if cm.serviceCache != nil {
		cm.serviceCache.Close()
	}
	if cm.applicationServiceRelationCache != nil {
		cm.applicationServiceRelationCache.Close()
	}
	if cm.relationshipCache != nil {
		cm.relationshipCache.Close()
	}
}

// ==================== Domain Cache ====================

// GetDomain 从缓存获取 Domain
func (cm *Manager) GetDomain(key string) (*models.DomainWithKey, bool) {
	if cm.domainCache == nil {
		return nil, false
	}
	return cm.domainCache.Get(key)
}

// SetDomain 设置 Domain 到缓存
func (cm *Manager) SetDomain(key string, value *models.DomainWithKey) {
	if cm.domainCache != nil {
		ttl := GetTTL("domain")
		cm.domainCache.SetWithTTL(key, value, 1, ttl)
	}
}

// ==================== Application Cache ====================

// GetApplication 从缓存获取 Application
func (cm *Manager) GetApplication(key string) (*models.ApplicationWithKey, bool) {
	if cm.applicationCache == nil {
		return nil, false
	}
	return cm.applicationCache.Get(key)
}

// SetApplication 设置 Application 到缓存
func (cm *Manager) SetApplication(key string, value *models.ApplicationWithKey) {
	if cm.applicationCache != nil {
		ttl := GetTTL("application")
		cm.applicationCache.SetWithTTL(key, value, 1, ttl)
	}
}

// ==================== Service Cache ====================

// GetService 从缓存获取 Service
func (cm *Manager) GetService(key string) (*models.ServiceWithKey, bool) {
	if cm.serviceCache == nil {
		return nil, false
	}
	return cm.serviceCache.Get(key)
}

// SetService 设置 Service 到缓存
func (cm *Manager) SetService(key string, value *models.ServiceWithKey) {
	if cm.serviceCache != nil {
		ttl := GetTTL("service")
		cm.serviceCache.SetWithTTL(key, value, 1, ttl)
	}
}

// ==================== ApplicationServiceRelation Cache ====================

// GetApplicationServiceRelation 从缓存获取 ApplicationServiceRelation
func (cm *Manager) GetApplicationServiceRelation(key string) ([]models.ApplicationServiceRelation, bool) {
	if cm.applicationServiceRelationCache == nil {
		return nil, false
	}
	return cm.applicationServiceRelationCache.Get(key)
}

// SetApplicationServiceRelation 设置 ApplicationServiceRelation 到缓存
func (cm *Manager) SetApplicationServiceRelation(key string, value []models.ApplicationServiceRelation) {
	if cm.applicationServiceRelationCache != nil {
		ttl := GetTTL("application-service-relation")
		cm.applicationServiceRelationCache.SetWithTTL(key, value, 1, ttl)
	}
}

// ==================== Relationship Cache ====================

// GetRelationship 从缓存获取 Relationship
func (cm *Manager) GetRelationship(key string) ([]models.Relationship, bool) {
	if cm.relationshipCache == nil {
		return nil, false
	}
	return cm.relationshipCache.Get(key)
}

// SetRelationship 设置 Relationship 到缓存
func (cm *Manager) SetRelationship(key string, value []models.Relationship) {
	if cm.relationshipCache != nil {
		ttl := GetTTL("relationship")
		cm.relationshipCache.SetWithTTL(key, value, 1, ttl)
	}
}
