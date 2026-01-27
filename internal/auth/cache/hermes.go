package cache

import (
	"context"

	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// HermesCache 带缓存的 hermes.Service 包装
// 只做缓存，解密由 hermes.Service 完成
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

// GetService 获取 Service（含解密密钥）
func (h *HermesCache) GetService(ctx context.Context, serviceID string) (*Service, error) {
	keyPrefix := GetKeyPrefix("service")
	cacheKey := keyPrefix + serviceID

	// 尝试从缓存获取
	if cached, ok := h.manager.GetService(cacheKey); ok {
		return cached, nil
	}

	// 从 hermes service 获取（已解密）
	result, err := h.svc.GetServiceWithKey(ctx, serviceID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	h.manager.SetService(cacheKey, result)

	return result, nil
}

// GetApplication 获取 Application（含解密密钥）
func (h *HermesCache) GetApplication(ctx context.Context, appID string) (*Application, error) {
	keyPrefix := GetKeyPrefix("application")
	cacheKey := keyPrefix + appID

	// 尝试从缓存获取
	if cached, ok := h.manager.GetApplication(cacheKey); ok {
		return cached, nil
	}

	// 从 hermes service 获取（已解密）
	result, err := h.svc.GetApplicationWithKey(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	h.manager.SetApplication(cacheKey, result)

	return result, nil
}

// GetDomain 获取 Domain（含签名密钥）
func (h *HermesCache) GetDomain(ctx context.Context, domainID string) (*Domain, error) {
	keyPrefix := GetKeyPrefix("domain")
	cacheKey := keyPrefix + domainID

	// 尝试从缓存获取
	if cached, ok := h.manager.GetDomain(cacheKey); ok {
		return cached, nil
	}

	// 从 hermes service 获取（含密钥）
	result, err := h.svc.GetDomainWithKey(ctx, domainID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	h.manager.SetDomain(cacheKey, result)

	return result, nil
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
