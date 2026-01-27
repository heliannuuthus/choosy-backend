package cache

import (
	"context"
	"encoding/base64"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/kms"
)

// HermesCache 带缓存的 hermes.Service 包装
type HermesCache struct {
	svc     *hermes.Service
	manager *Manager
}

// NewHermesCache 创建 HermesCache
func NewHermesCache(svc *hermes.Service) *HermesCache {
	manager := NewManager()

	return &HermesCache{
		svc:     svc,
		manager: manager,
	}
}

// GetServiceWithKey 获取带解密密钥的 Service
func (h *HermesCache) GetServiceWithKey(ctx context.Context, serviceID string) (*ServiceWithKey, error) {
	keyPrefix := GetKeyPrefix("service")
	cacheKey := keyPrefix + serviceID

	// 尝试从缓存获取
	if cached, ok := h.manager.GetService(cacheKey); ok {
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
	h.manager.SetService(cacheKey, result)

	return result, nil
}

// GetApplication 获取 Application（含密钥）
func (h *HermesCache) GetApplication(ctx context.Context, appID string) (*ApplicationWithKey, error) {
	keyPrefix := GetKeyPrefix("application")
	cacheKey := keyPrefix + appID

	// 尝试从缓存获取
	if cached, ok := h.manager.GetApplication(cacheKey); ok {
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
	h.manager.SetApplication(cacheKey, result)

	return result, nil
}

// GetService 获取 Service（不解密）
func (h *HermesCache) GetService(ctx context.Context, serviceID string) (*models.Service, error) {
	keyPrefix := GetKeyPrefix("service")
	cacheKey := keyPrefix + serviceID

	// 尝试从缓存获取（需要从 ServiceWithKey 中提取）
	if cached, ok := h.manager.GetService(cacheKey); ok {
		svc := cached.Service
		return &svc, nil
	}

	// 查库
	svc, err := h.svc.GetService(ctx, serviceID)
	if err != nil {
		return nil, err
	}

	// 存入缓存（作为 ServiceWithKey，但这里只存 Service 部分）
	key, _ := h.decryptKey(svc)
	result := &ServiceWithKey{Service: *svc, Key: key}
	h.manager.SetService(cacheKey, result)

	return svc, nil
}

// GetDomain 获取 Domain（含密钥）
func (h *HermesCache) GetDomain(ctx context.Context, domainID string) (*DomainWithKey, error) {
	keyPrefix := GetKeyPrefix("domain")
	cacheKey := keyPrefix + domainID

	// 尝试从缓存获取
	if cached, ok := h.manager.GetDomain(cacheKey); ok {
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
	h.manager.SetDomain(cacheKey, result)

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
	if h.manager != nil {
		h.manager.Close()
	}
}

// CheckApplicationServiceRelation 检查应用是否有权访问服务
func (h *HermesCache) CheckApplicationServiceRelation(ctx context.Context, appID, serviceID string) (bool, error) {
	keyPrefix := GetKeyPrefix("application-service-relation")
	cacheKey := keyPrefix + appID

	// 尝试从缓存获取
	relations, ok := h.manager.GetApplicationServiceRelation(cacheKey)
	if !ok {
		// 缓存未命中，查库
		var err error
		relations, err = h.svc.GetApplicationServiceRelations(ctx, appID)
		if err != nil {
			return false, err
		}

		// 存入缓存
		h.manager.SetApplicationServiceRelation(cacheKey, relations)
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
	keyPrefix := GetKeyPrefix("application-service-relation")
	cacheKey := keyPrefix + appID

	// 尝试从缓存获取
	if cached, ok := h.manager.GetApplicationServiceRelation(cacheKey); ok {
		return cached, nil
	}

	// 查库
	relations, err := h.svc.GetApplicationServiceRelations(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	h.manager.SetApplicationServiceRelation(cacheKey, relations)

	return relations, nil
}
