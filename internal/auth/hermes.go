package auth

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/kms"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// ServiceWithKey 带解密密钥的 Service
type ServiceWithKey struct {
	models.Service
	Key []byte // 解密后的密钥
}

// ApplicationWithKey 带解密密钥的 Application
type ApplicationWithKey struct {
	models.Application
	Key []byte // 解密后的密钥（如果存在）
}

// DomainWithKey 带解密密钥的 Domain
type DomainWithKey struct {
	models.Domain
	SignKey    []byte // 签名密钥
	EncryptKey []byte // 加密密钥
}

// CacheManager 缓存管理器，为每个类型管理独立的 cache
// 配置从全局 viper 动态读取，支持热更新
// 每个 cache 类型都有独立的配置前缀：auth.cache.{type}.{config-key}
type CacheManager struct {
	domainCache                    *ristretto.Cache[string, *DomainWithKey]
	applicationCache               *ristretto.Cache[string, *ApplicationWithKey]
	serviceCache                   *ristretto.Cache[string, *ServiceWithKey]
	userCache                      *ristretto.Cache[string, *User]
	applicationServiceRelationCache *ristretto.Cache[string, []models.ApplicationServiceRelation]
	relationshipCache              *ristretto.Cache[string, []models.Relationship]
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

// getTTL 从全局 viper 获取指定 cache 类型的 TTL
func getTTL(cacheType string) time.Duration {
	v := config.V()
	prefix := "auth.cache." + cacheType + "."
	defaultTTL := 2 * time.Minute

	if ttl := v.GetDuration(prefix + "ttl"); ttl > 0 {
		return ttl
	}
	return defaultTTL
}

// getKeyPrefix 从全局 viper 获取指定 cache 类型的 key 前缀
func getKeyPrefix(cacheType string) string {
	v := config.V()
	prefix := "auth.cache." + cacheType + "."

	// 默认前缀映射
	defaultPrefixes := map[string]string{
		"domain":                    "domain:",
		"application":               "app:",
		"service":                   "svc:",
		"user":                      "user:",
		"application-service-relation": "app-svc-rel:",
		"relationship":              "rel:",
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

// newCacheManager 创建缓存管理器
// 所有配置都从全局 viper 读取，支持热更新
func newCacheManager() *CacheManager {
	cm := &CacheManager{}

	// 创建 Domain cache
	maxCost, numCounters, bufferItems := getCacheConfig("domain")
	domainCache, err := ristretto.NewCache(&ristretto.Config[string, *DomainWithKey]{
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
	applicationCache, err := ristretto.NewCache(&ristretto.Config[string, *ApplicationWithKey]{
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
	serviceCache, err := ristretto.NewCache(&ristretto.Config[string, *ServiceWithKey]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[CacheManager] 创建 Service 缓存失败: %v", err)
	} else {
		cm.serviceCache = serviceCache
	}

	// 创建 User cache
	maxCost, numCounters, bufferItems = getCacheConfig("user")
	userCache, err := ristretto.NewCache(&ristretto.Config[string, *User]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[CacheManager] 创建 User 缓存失败: %v", err)
	} else {
		cm.userCache = userCache
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
func (cm *CacheManager) Close() {
	if cm.domainCache != nil {
		cm.domainCache.Close()
	}
	if cm.applicationCache != nil {
		cm.applicationCache.Close()
	}
	if cm.serviceCache != nil {
		cm.serviceCache.Close()
	}
	if cm.userCache != nil {
		cm.userCache.Close()
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
func (cm *CacheManager) GetDomain(key string) (*DomainWithKey, bool) {
	if cm.domainCache == nil {
		return nil, false
	}
	return cm.domainCache.Get(key)
}

// SetDomain 设置 Domain 到缓存
func (cm *CacheManager) SetDomain(key string, value *DomainWithKey) {
	if cm.domainCache != nil {
		ttl := getTTL("domain")
		cm.domainCache.SetWithTTL(key, value, 1, ttl)
	}
}

// ==================== Application Cache ====================

// GetApplication 从缓存获取 Application
func (cm *CacheManager) GetApplication(key string) (*ApplicationWithKey, bool) {
	if cm.applicationCache == nil {
		return nil, false
	}
	return cm.applicationCache.Get(key)
}

// SetApplication 设置 Application 到缓存
func (cm *CacheManager) SetApplication(key string, value *ApplicationWithKey) {
	if cm.applicationCache != nil {
		ttl := getTTL("application")
		cm.applicationCache.SetWithTTL(key, value, 1, ttl)
	}
}

// ==================== Service Cache ====================

// GetService 从缓存获取 Service
func (cm *CacheManager) GetService(key string) (*ServiceWithKey, bool) {
	if cm.serviceCache == nil {
		return nil, false
	}
	return cm.serviceCache.Get(key)
}

// SetService 设置 Service 到缓存
func (cm *CacheManager) SetService(key string, value *ServiceWithKey) {
	if cm.serviceCache != nil {
		ttl := getTTL("service")
		cm.serviceCache.SetWithTTL(key, value, 1, ttl)
	}
}

// ==================== User Cache ====================

// GetUser 从缓存获取 User
func (cm *CacheManager) GetUser(key string) (*User, bool) {
	if cm.userCache == nil {
		return nil, false
	}
	return cm.userCache.Get(key)
}

// SetUser 设置 User 到缓存
func (cm *CacheManager) SetUser(key string, value *User) {
	if cm.userCache != nil {
		ttl := getTTL("user")
		cm.userCache.SetWithTTL(key, value, 1, ttl)
	}
}

// ==================== ApplicationServiceRelation Cache ====================

// GetApplicationServiceRelation 从缓存获取 ApplicationServiceRelation
func (cm *CacheManager) GetApplicationServiceRelation(key string) ([]models.ApplicationServiceRelation, bool) {
	if cm.applicationServiceRelationCache == nil {
		return nil, false
	}
	return cm.applicationServiceRelationCache.Get(key)
}

// SetApplicationServiceRelation 设置 ApplicationServiceRelation 到缓存
func (cm *CacheManager) SetApplicationServiceRelation(key string, value []models.ApplicationServiceRelation) {
	if cm.applicationServiceRelationCache != nil {
		ttl := getTTL("application-service-relation")
		cm.applicationServiceRelationCache.SetWithTTL(key, value, 1, ttl)
	}
}

// ==================== Relationship Cache ====================

// GetRelationship 从缓存获取 Relationship
func (cm *CacheManager) GetRelationship(key string) ([]models.Relationship, bool) {
	if cm.relationshipCache == nil {
		return nil, false
	}
	return cm.relationshipCache.Get(key)
}

// SetRelationship 设置 Relationship 到缓存
func (cm *CacheManager) SetRelationship(key string, value []models.Relationship) {
	if cm.relationshipCache != nil {
		ttl := getTTL("relationship")
		cm.relationshipCache.SetWithTTL(key, value, 1, ttl)
	}
}

// HermesCache 带缓存的 hermes.Service 包装
type HermesCache struct {
	svc          *hermes.Service
	cacheManager *CacheManager
}

// NewHermesCache 创建 HermesCache
func NewHermesCache(svc *hermes.Service) *HermesCache {
	cacheManager := newCacheManager()

	return &HermesCache{
		svc:          svc,
		cacheManager: cacheManager,
	}
}

// GetServiceWithKey 获取带解密密钥的 Service
func (h *HermesCache) GetServiceWithKey(ctx context.Context, serviceID string) (*ServiceWithKey, error) {
	keyPrefix := getKeyPrefix("service")
	cacheKey := keyPrefix + serviceID

	// 尝试从缓存获取
	if cached, ok := h.cacheManager.GetService(cacheKey); ok {
		return cached, nil
	}

	// 查库
	svc, err := h.svc.GetService(ctx, serviceID)
	if err != nil {
		return nil, err
	}

	// 解密密钥
	key, err := h.decryptKey(svc)
	if err != nil {
		return nil, err
	}

	result := &ServiceWithKey{Service: *svc, Key: key}

	// 存入缓存
	h.cacheManager.SetService(cacheKey, result)

	return result, nil
}

// GetApplication 获取 Application（含密钥）
func (h *HermesCache) GetApplication(ctx context.Context, appID string) (*ApplicationWithKey, error) {
	keyPrefix := getKeyPrefix("application")
	cacheKey := keyPrefix + appID

	// 尝试从缓存获取
	if cached, ok := h.cacheManager.GetApplication(cacheKey); ok {
		return cached, nil
	}

	// 查库
	app, err := h.svc.GetApplication(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 解密密钥（如果存在）
	var key []byte
	if app.EncryptedKey != nil && *app.EncryptedKey != "" {
		domainKey, err := config.GetDomainEncryptKey(app.DomainID)
		if err != nil {
			return nil, err
		}

		encrypted, err := base64.StdEncoding.DecodeString(*app.EncryptedKey)
		if err != nil {
			return nil, err
		}

		key, err = kms.DecryptAESGCM(domainKey, encrypted, app.AppID)
		if err != nil {
			return nil, err
		}
	}

	result := &ApplicationWithKey{Application: *app, Key: key}

	// 存入缓存
	h.cacheManager.SetApplication(cacheKey, result)

	return result, nil
}

// GetService 获取 Service（不解密）
func (h *HermesCache) GetService(ctx context.Context, serviceID string) (*models.Service, error) {
	keyPrefix := getKeyPrefix("service")
	cacheKey := keyPrefix + serviceID

	// 尝试从缓存获取（需要从 ServiceWithKey 中提取）
	if cached, ok := h.cacheManager.GetService(cacheKey); ok {
		svc := cached.Service
		return &svc, nil
	}

	// 查库
	svc, err := h.svc.GetService(ctx, serviceID)
	if err != nil {
		return nil, err
	}

	// 存入缓存（作为 ServiceWithKey，但这里只存 Service 部分）
	// 注意：这里可以优化，但为了保持 API 一致性，先这样实现
	key, _ := h.decryptKey(svc)
	result := &ServiceWithKey{Service: *svc, Key: key}
	h.cacheManager.SetService(cacheKey, result)

	return svc, nil
}

// GetDomain 获取 Domain（含密钥）
func (h *HermesCache) GetDomain(ctx context.Context, domainID string) (*DomainWithKey, error) {
	keyPrefix := getKeyPrefix("domain")
	cacheKey := keyPrefix + domainID

	// 尝试从缓存获取
	if cached, ok := h.cacheManager.GetDomain(cacheKey); ok {
		return cached, nil
	}

	// 查库
	domain, err := h.svc.GetDomain(ctx, domainID)
	if err != nil {
		return nil, err
	}

	// 获取密钥
	signKey, err := config.GetDomainSignKey(domainID)
	if err != nil {
		return nil, err
	}

	encryptKey, err := config.GetDomainEncryptKey(domainID)
	if err != nil {
		return nil, err
	}

	result := &DomainWithKey{
		Domain:     *domain,
		SignKey:    signKey,
		EncryptKey: encryptKey,
	}

	// 存入缓存
	h.cacheManager.SetDomain(cacheKey, result)

	return result, nil
}

// decryptKey 解密 Service 密钥
func (h *HermesCache) decryptKey(svc *models.Service) ([]byte, error) {
	domainKey, err := config.GetDomainEncryptKey(svc.DomainID)
	if err != nil {
		return nil, err
	}

	encrypted, err := base64.StdEncoding.DecodeString(svc.EncryptedKey)
	if err != nil {
		return nil, err
	}

	return kms.DecryptAESGCM(domainKey, encrypted, svc.ServiceID)
}

// Close 关闭缓存
func (h *HermesCache) Close() {
	if h.cacheManager != nil {
		h.cacheManager.Close()
	}
}

// CheckApplicationServiceRelation 检查应用是否有权访问服务
// 利用 applicationServiceRelationCache 进行缓存
// 返回 true 表示有权限，false 表示无权限
func (h *HermesCache) CheckApplicationServiceRelation(ctx context.Context, appID, serviceID string) (bool, error) {
	keyPrefix := getKeyPrefix("application-service-relation")
	cacheKey := keyPrefix + appID

	// 尝试从缓存获取
	relations, ok := h.cacheManager.GetApplicationServiceRelation(cacheKey)
	if !ok {
		// 缓存未命中，查库
		var err error
		relations, err = h.svc.GetApplicationServiceRelations(ctx, appID)
		if err != nil {
			return false, err
		}

		// 存入缓存
		h.cacheManager.SetApplicationServiceRelation(cacheKey, relations)
	}

	// 检查是否有指定 serviceID 的关系
	for _, rel := range relations {
		if rel.ServiceID == serviceID {
			return true, nil
		}
	}

	return false, nil
}

// GetApplicationServiceRelations 获取应用可访问的服务关系列表
func (h *HermesCache) GetApplicationServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error) {
	keyPrefix := getKeyPrefix("application-service-relation")
	cacheKey := keyPrefix + appID

	// 尝试从缓存获取
	if cached, ok := h.cacheManager.GetApplicationServiceRelation(cacheKey); ok {
		return cached, nil
	}

	// 查库
	relations, err := h.svc.GetApplicationServiceRelations(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	h.cacheManager.SetApplicationServiceRelation(cacheKey, relations)

	return relations, nil
}
