package hermes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/database"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/kms"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Service 管理服务
type Service struct {
	db *gorm.DB
}

// NewService 创建管理服务
func NewService() *Service {
	return &Service{
		db: database.GetAuth(),
	}
}

// ==================== Domain 相关 ====================

// GetDomain 获取域（从配置读取，不含密钥）
func (*Service) GetDomain(ctx context.Context, domainID string) (*models.Domain, error) {
	domainConfig, err := config.GetDomainConfig(domainID)
	if err != nil {
		return nil, fmt.Errorf("获取域失败: %w", err)
	}

	name := domainConfig.Name
	if name == "" {
		name = domainID
	}

	var description *string
	if domainConfig.Description != "" {
		description = &domainConfig.Description
	}

	domain := &models.Domain{
		DomainID:    domainID,
		Name:        name,
		Description: description,
	}

	return domain, nil
}

// GetDomainWithKey 获取域（含签名密钥）
func (s *Service) GetDomainWithKey(ctx context.Context, domainID string) (*models.DomainWithKey, error) {
	domain, err := s.GetDomain(ctx, domainID)
	if err != nil {
		return nil, err
	}

	// 获取签名密钥
	signKey, err := config.GetDomainSignKey(domainID)
	if err != nil {
		return nil, fmt.Errorf("获取域签名密钥失败: %w", err)
	}

	return &models.DomainWithKey{Domain: *domain, SignKey: signKey}, nil
}

// ListDomains 列出所有域（从配置读取）
func (*Service) ListDomains(ctx context.Context) ([]models.Domain, error) {
	authConfig := config.GetAuthConfig()
	if authConfig == nil {
		return nil, fmt.Errorf("auth 配置未初始化")
	}

	domains := make([]models.Domain, 0, len(authConfig.Domains))
	for domainID, domainConfig := range authConfig.Domains {
		name := domainConfig.Name
		if name == "" {
			name = domainID
		}

		var description *string
		if domainConfig.Description != "" {
			description = &domainConfig.Description
		}

		domain := models.Domain{
			DomainID:    domainID,
			Name:        name,
			Description: description,
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

// ==================== Service 相关 ====================

// generateServiceKey 生成服务密钥并加密
func (*Service) generateServiceKey(domainID string) (string, error) {
	// 生成 AES-256 密钥
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("生成密钥失败: %w", err)
	}

	// 获取域加密密钥
	domainEncryptKey, err := config.GetDomainEncryptKey(domainID)
	if err != nil {
		return "", fmt.Errorf("获取域加密密钥失败: %w", err)
	}

	// 用域密钥加密服务密钥（AES-GCM，AAD=serviceID）
	encryptedKey, err := kms.EncryptAESGCM(key, domainEncryptKey, domainID)
	if err != nil {
		return "", fmt.Errorf("加密服务密钥失败: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// CreateService 创建服务
func (s *Service) CreateService(ctx context.Context, req *ServiceCreateRequest) (*models.Service, error) {
	// 生成并加密服务密钥
	encryptedKey, err := s.generateServiceKey(req.DomainID)
	if err != nil {
		return nil, err
	}

	service := &models.Service{
		ServiceID:             req.ServiceID,
		DomainID:              req.DomainID,
		Name:                  req.Name,
		Description:           req.Description,
		EncryptedKey:          encryptedKey,
		AccessTokenExpiresIn:  7200,
		RefreshTokenExpiresIn: 604800,
		Status:                0,
	}

	if req.AccessTokenExpiresIn != nil {
		service.AccessTokenExpiresIn = *req.AccessTokenExpiresIn
	}
	if req.RefreshTokenExpiresIn != nil {
		service.RefreshTokenExpiresIn = *req.RefreshTokenExpiresIn
	}

	if err := s.db.WithContext(ctx).Create(service).Error; err != nil {
		return nil, fmt.Errorf("创建服务失败: %w", err)
	}

	return service, nil
}

// GetService 获取服务（不含密钥）
func (s *Service) GetService(ctx context.Context, serviceID string) (*models.Service, error) {
	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return nil, fmt.Errorf("获取服务失败: %w", err)
	}
	return &service, nil
}

// GetServiceWithKey 获取服务（含解密密钥）
func (s *Service) GetServiceWithKey(ctx context.Context, serviceID string) (*models.ServiceWithKey, error) {
	service, err := s.GetService(ctx, serviceID)
	if err != nil {
		return nil, err
	}

	// 解密密钥
	key, err := s.decryptServiceKey(service)
	if err != nil {
		return nil, err
	}

	return &models.ServiceWithKey{Service: *service, Key: key}, nil
}

// decryptServiceKey 解密服务密钥
func (s *Service) decryptServiceKey(svc *models.Service) ([]byte, error) {
	domainKey, err := config.GetDomainEncryptKey(svc.DomainID)
	if err != nil {
		return nil, fmt.Errorf("获取域加密密钥失败: %w", err)
	}

	encrypted, err := base64.StdEncoding.DecodeString(svc.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("解码服务密钥失败: %w", err)
	}

	key, err := kms.DecryptAESGCM(domainKey, encrypted, svc.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("解密服务密钥失败: %w", err)
	}

	return key, nil
}

// ListServices 列出所有服务
func (s *Service) ListServices(ctx context.Context, domainID string) ([]models.Service, error) {
	var services []models.Service
	query := s.db.WithContext(ctx)
	if domainID != "" {
		query = query.Where("domain_id = ?", domainID)
	}
	if err := query.Find(&services).Error; err != nil {
		return nil, fmt.Errorf("列出服务失败: %w", err)
	}
	return services, nil
}

// UpdateService 更新服务
func (s *Service) UpdateService(ctx context.Context, serviceID string, req *ServiceUpdateRequest) error {
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.AccessTokenExpiresIn != nil {
		updates["access_token_expires_in"] = *req.AccessTokenExpiresIn
	}
	if req.RefreshTokenExpiresIn != nil {
		updates["refresh_token_expires_in"] = *req.RefreshTokenExpiresIn
	}
	if req.Status != nil {
		updates["status"] = *req.Status
	}

	if len(updates) == 0 {
		return nil
	}

	if err := s.db.WithContext(ctx).Model(&models.Service{}).
		Where("service_id = ?", serviceID).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新服务失败: %w", err)
	}

	return nil
}

// ==================== Application 相关 ====================

// generateApplicationKey 生成应用密钥并加密
func (s *Service) generateApplicationKey(domainID, appID string) (string, error) {
	// 生成 AES-256 密钥
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("生成密钥失败: %w", err)
	}

	// 获取域加密密钥
	domainEncryptKey, err := config.GetDomainEncryptKey(domainID)
	if err != nil {
		return "", fmt.Errorf("获取域加密密钥失败: %w", err)
	}

	// 用域密钥加密应用密钥（AES-GCM，AAD=appID）
	encryptedKey, err := kms.EncryptAESGCM(key, domainEncryptKey, appID)
	if err != nil {
		return "", fmt.Errorf("加密应用密钥失败: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// CreateApplication 创建应用
func (s *Service) CreateApplication(ctx context.Context, req *ApplicationCreateRequest) (*models.Application, error) {
	var redirectURIs *string
	if len(req.RedirectURIs) > 0 {
		urisJSON, err := json.Marshal(req.RedirectURIs)
		if err != nil {
			return nil, fmt.Errorf("marshal redirect uris: %w", err)
		}
		urisStr := string(urisJSON)
		redirectURIs = &urisStr
	}

	var encryptedKey *string
	if req.NeedKey {
		key, err := s.generateApplicationKey(req.DomainID, req.AppID)
		if err != nil {
			return nil, err
		}
		encryptedKey = &key
	}

	app := &models.Application{
		DomainID:     req.DomainID,
		AppID:        req.AppID,
		Name:         req.Name,
		RedirectURIs: redirectURIs,
		EncryptedKey: encryptedKey,
	}

	if err := s.db.WithContext(ctx).Create(app).Error; err != nil {
		return nil, fmt.Errorf("创建应用失败: %w", err)
	}

	return app, nil
}

// GetApplication 获取应用（不含密钥）
func (s *Service) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("获取应用失败: %w", err)
	}
	return &app, nil
}

// GetApplicationWithKey 获取应用（含解密密钥）
func (s *Service) GetApplicationWithKey(ctx context.Context, appID string) (*models.ApplicationWithKey, error) {
	app, err := s.GetApplication(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 解密密钥（如果存在）
	var key []byte
	if app.EncryptedKey != nil && *app.EncryptedKey != "" {
		key, err = s.decryptApplicationKey(app)
		if err != nil {
			return nil, err
		}
	}

	return &models.ApplicationWithKey{Application: *app, Key: key}, nil
}

// decryptApplicationKey 解密应用密钥
func (s *Service) decryptApplicationKey(app *models.Application) ([]byte, error) {
	if app.EncryptedKey == nil || *app.EncryptedKey == "" {
		return nil, nil
	}

	domainKey, err := config.GetDomainEncryptKey(app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("获取域加密密钥失败: %w", err)
	}

	encrypted, err := base64.StdEncoding.DecodeString(*app.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("解码应用密钥失败: %w", err)
	}

	key, err := kms.DecryptAESGCM(domainKey, encrypted, app.AppID)
	if err != nil {
		return nil, fmt.Errorf("解密应用密钥失败: %w", err)
	}

	return key, nil
}

// ListApplications 列出所有应用
func (s *Service) ListApplications(ctx context.Context, domainID string) ([]models.Application, error) {
	var apps []models.Application
	query := s.db.WithContext(ctx)
	if domainID != "" {
		query = query.Where("domain_id = ?", domainID)
	}
	if err := query.Find(&apps).Error; err != nil {
		return nil, fmt.Errorf("列出应用失败: %w", err)
	}
	return apps, nil
}

// UpdateApplication 更新应用
func (s *Service) UpdateApplication(ctx context.Context, appID string, req *ApplicationUpdateRequest) error {
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if len(req.RedirectURIs) > 0 {
		urisJSON, _ := json.Marshal(req.RedirectURIs)
		updates["redirect_uris"] = string(urisJSON)
	}

	if len(updates) == 0 {
		return nil
	}

	if err := s.db.WithContext(ctx).Model(&models.Application{}).
		Where("app_id = ?", appID).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新应用失败: %w", err)
	}

	return nil
}

// SetApplicationServiceRelations 设置应用可访问的服务和关系
func (s *Service) SetApplicationServiceRelations(ctx context.Context, req *ApplicationServiceRelationRequest) error {
	// 先删除旧的关系
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", req.AppID, req.ServiceID).
		Delete(&models.ApplicationServiceRelation{}).Error; err != nil {
		return fmt.Errorf("删除旧关系失败: %w", err)
	}

	// 插入新关系
	for _, relation := range req.Relations {
		rel := &models.ApplicationServiceRelation{
			AppID:     req.AppID,
			ServiceID: req.ServiceID,
			Relation:  relation,
		}
		if err := s.db.WithContext(ctx).Create(rel).Error; err != nil {
			logger.Errorf("创建应用服务关系失败: %v", err)
		}
	}

	return nil
}

// GetApplicationServiceRelations 获取应用可访问的服务和关系
func (s *Service) GetApplicationServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error) {
	var relations []models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).Find(&relations).Error; err != nil {
		return nil, fmt.Errorf("获取应用服务关系失败: %w", err)
	}
	return relations, nil
}

// ==================== Relationship 相关 ====================

// CreateRelationship 创建关系
func (s *Service) CreateRelationship(ctx context.Context, req *RelationshipCreateRequest) (*models.Relationship, error) {
	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("解析过期时间失败: %w", err)
		}
		expiresAt = &exp
	}

	rel := &models.Relationship{
		ServiceID:   req.ServiceID,
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		Relation:    req.Relation,
		ObjectType:  req.ObjectType,
		ObjectID:    req.ObjectID,
		ExpiresAt:   expiresAt,
	}

	if err := s.db.WithContext(ctx).Create(rel).Error; err != nil {
		return nil, fmt.Errorf("创建关系失败: %w", err)
	}

	return rel, nil
}

// DeleteRelationship 删除关系
func (s *Service) DeleteRelationship(ctx context.Context, req *RelationshipDeleteRequest) error {
	if err := s.db.WithContext(ctx).Where(
		"service_id = ? AND subject_type = ? AND subject_id = ? AND relation = ? AND object_type = ? AND object_id = ?",
		req.ServiceID, req.SubjectType, req.SubjectID, req.Relation, req.ObjectType, req.ObjectID,
	).Delete(&models.Relationship{}).Error; err != nil {
		return fmt.Errorf("删除关系失败: %w", err)
	}

	return nil
}

// ListRelationships 列出关系
func (s *Service) ListRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]models.Relationship, error) {
	var rels []models.Relationship
	query := s.db.WithContext(ctx).Where("service_id = ?", serviceID)
	if subjectType != "" {
		query = query.Where("subject_type = ?", subjectType)
	}
	if subjectID != "" {
		query = query.Where("subject_id = ?", subjectID)
	}
	if err := query.Find(&rels).Error; err != nil {
		return nil, fmt.Errorf("列出关系失败: %w", err)
	}
	return rels, nil
}

// UpdateRelationship 更新关系
func (s *Service) UpdateRelationship(ctx context.Context, req *RelationshipUpdateRequest) (*models.Relationship, error) {
	// 1. 查找关系
	var rel models.Relationship
	if err := s.db.WithContext(ctx).Where(
		"service_id = ? AND subject_type = ? AND subject_id = ? AND relation = ? AND object_type = ? AND object_id = ?",
		req.ServiceID, req.SubjectType, req.SubjectID, req.Relation, req.ObjectType, req.ObjectID,
	).First(&rel).Error; err != nil {
		return nil, fmt.Errorf("关系不存在: %w", err)
	}

	// 2. 构建更新字段
	updates := make(map[string]interface{})

	// 更新关系类型（如果提供）
	if req.NewRelation != nil && *req.NewRelation != "" {
		updates["relation"] = *req.NewRelation
	}

	// 更新过期时间（如果提供）
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			// 传空字符串表示清除过期时间
			updates["expires_at"] = nil
		} else {
			// 解析 ISO 8601 格式的过期时间
			exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("解析过期时间失败: %w", err)
			}
			updates["expires_at"] = exp
		}
	}

	// 3. 如果没有要更新的字段，直接返回
	if len(updates) == 0 {
		return &rel, nil
	}

	// 4. 更新关系
	if err := s.db.WithContext(ctx).Model(&rel).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新关系失败: %w", err)
	}

	// 5. 重新查询返回更新后的关系
	if err := s.db.WithContext(ctx).First(&rel, rel.ID).Error; err != nil {
		return nil, fmt.Errorf("获取更新后的关系失败: %w", err)
	}

	return &rel, nil
}

// ==================== App Service Relationship 相关（RESTful 风格）====================

// ListAppServiceRelationships 列出应用服务下的关系
func (s *Service) ListAppServiceRelationships(ctx context.Context, appID, serviceID, subjectType, subjectID string) ([]models.Relationship, error) {
	// 1. 验证应用和服务是否存在
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("应用不存在: %w", err)
	}

	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return nil, fmt.Errorf("服务不存在: %w", err)
	}

	// 2. 验证应用是否有权限访问该服务
	var relation models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", appID, serviceID).First(&relation).Error; err != nil {
		return nil, fmt.Errorf("应用无权访问该服务")
	}

	// 3. 查询关系
	var rels []models.Relationship
	query := s.db.WithContext(ctx).Where("service_id = ?", serviceID)
	if subjectType != "" {
		query = query.Where("subject_type = ?", subjectType)
	}
	if subjectID != "" {
		query = query.Where("subject_id = ?", subjectID)
	}
	if err := query.Find(&rels).Error; err != nil {
		return nil, fmt.Errorf("列出关系失败: %w", err)
	}
	return rels, nil
}

// CreateAppServiceRelationship 在应用服务下创建关系
func (s *Service) CreateAppServiceRelationship(ctx context.Context, appID, serviceID string, req *AppServiceRelationshipCreateRequest) (*models.Relationship, error) {
	// 1. 验证应用和服务是否存在
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("应用不存在: %w", err)
	}

	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return nil, fmt.Errorf("服务不存在: %w", err)
	}

	// 2. 验证应用是否有权限访问该服务
	var relation models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", appID, serviceID).First(&relation).Error; err != nil {
		return nil, fmt.Errorf("应用无权访问该服务")
	}

	// 3. 解析过期时间
	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("解析过期时间失败: %w", err)
		}
		expiresAt = &exp
	}

	// 4. 创建关系
	rel := &models.Relationship{
		ServiceID:   serviceID,
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		Relation:    req.Relation,
		ObjectType:  req.ObjectType,
		ObjectID:    req.ObjectID,
		ExpiresAt:   expiresAt,
	}

	if err := s.db.WithContext(ctx).Create(rel).Error; err != nil {
		return nil, fmt.Errorf("创建关系失败: %w", err)
	}

	return rel, nil
}

// UpdateAppServiceRelationship 在应用服务下更新关系
func (s *Service) UpdateAppServiceRelationship(ctx context.Context, appID, serviceID string, relationshipID uint, req *AppServiceRelationshipUpdateRequest) (*models.Relationship, error) {
	// 1. 验证应用和服务是否存在
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("应用不存在: %w", err)
	}

	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return nil, fmt.Errorf("服务不存在: %w", err)
	}

	// 2. 验证应用是否有权限访问该服务
	var relation models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", appID, serviceID).First(&relation).Error; err != nil {
		return nil, fmt.Errorf("应用无权访问该服务")
	}

	// 3. 查找关系（通过 ID 和 service_id）
	var rel models.Relationship
	if err := s.db.WithContext(ctx).Where("_id = ? AND service_id = ?", relationshipID, serviceID).First(&rel).Error; err != nil {
		return nil, fmt.Errorf("关系不存在: %w", err)
	}

	// 4. 构建更新字段
	updates := make(map[string]interface{})

	// 更新关系类型（如果提供）
	if req.NewRelation != nil && *req.NewRelation != "" {
		updates["relation"] = *req.NewRelation
	}

	// 更新过期时间（如果提供）
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			// 传空字符串表示清除过期时间
			updates["expires_at"] = nil
		} else {
			// 解析 ISO 8601 格式的过期时间
			exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("解析过期时间失败: %w", err)
			}
			updates["expires_at"] = exp
		}
	}

	// 5. 如果没有要更新的字段，直接返回
	if len(updates) == 0 {
		return &rel, nil
	}

	// 6. 更新关系
	if err := s.db.WithContext(ctx).Model(&rel).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新关系失败: %w", err)
	}

	// 7. 重新查询返回更新后的关系
	if err := s.db.WithContext(ctx).First(&rel, rel.ID).Error; err != nil {
		return nil, fmt.Errorf("获取更新后的关系失败: %w", err)
	}

	return &rel, nil
}

// DeleteAppServiceRelationship 在应用服务下删除关系
func (s *Service) DeleteAppServiceRelationship(ctx context.Context, appID, serviceID string, relationshipID uint) error {
	// 1. 验证应用和服务是否存在
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return fmt.Errorf("应用不存在: %w", err)
	}

	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return fmt.Errorf("服务不存在: %w", err)
	}

	// 2. 验证应用是否有权限访问该服务
	var relation models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", appID, serviceID).First(&relation).Error; err != nil {
		return fmt.Errorf("应用无权访问该服务")
	}

	// 3. 删除关系（通过 ID 和 service_id）
	if err := s.db.WithContext(ctx).Where("_id = ? AND service_id = ?", relationshipID, serviceID).Delete(&models.Relationship{}).Error; err != nil {
		return fmt.Errorf("删除关系失败: %w", err)
	}

	return nil
}

// ==================== Group 相关 ====================

// CreateGroup 创建组
func (s *Service) CreateGroup(ctx context.Context, req *GroupCreateRequest) (*models.Group, error) {
	group := &models.Group{
		GroupID:     req.GroupID,
		Name:        req.Name,
		Description: req.Description,
	}

	if err := s.db.WithContext(ctx).Create(group).Error; err != nil {
		return nil, fmt.Errorf("创建组失败: %w", err)
	}

	return group, nil
}

// GetGroup 获取组
func (s *Service) GetGroup(ctx context.Context, groupID string) (*models.Group, error) {
	var group models.Group
	if err := s.db.WithContext(ctx).Where("group_id = ?", groupID).First(&group).Error; err != nil {
		return nil, fmt.Errorf("获取组失败: %w", err)
	}
	return &group, nil
}

// ListGroups 列出所有组
func (s *Service) ListGroups(ctx context.Context) ([]models.Group, error) {
	var groups []models.Group
	if err := s.db.WithContext(ctx).Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("列出组失败: %w", err)
	}
	return groups, nil
}

// UpdateGroup 更新组
func (s *Service) UpdateGroup(ctx context.Context, groupID string, req *GroupUpdateRequest) error {
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}

	if len(updates) == 0 {
		return nil
	}

	if err := s.db.WithContext(ctx).Model(&models.Group{}).
		Where("group_id = ?", groupID).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新组失败: %w", err)
	}

	return nil
}

// SetGroupMembers 设置组成员（通过关系表）
// 注意：组成员关系使用 service_id = "system" 表示系统级别关系
func (s *Service) SetGroupMembers(ctx context.Context, req *GroupMemberRequest) error {
	// 先删除旧的成员关系
	if err := s.db.WithContext(ctx).Where("service_id = ? AND object_type = ? AND object_id = ? AND relation = ?", "system", "group", req.GroupID, "member").
		Delete(&models.Relationship{}).Error; err != nil {
		return fmt.Errorf("删除旧成员关系失败: %w", err)
	}

	// 插入新成员关系
	for _, userID := range req.UserIDs {
		rel := &models.Relationship{
			ServiceID:   "system", // 系统级别关系
			SubjectType: "user",
			SubjectID:   userID,
			Relation:    "member",
			ObjectType:  "group",
			ObjectID:    req.GroupID,
		}
		if err := s.db.WithContext(ctx).Create(rel).Error; err != nil {
			logger.Errorf("创建组成员关系失败: %v", err)
		}
	}

	return nil
}

// GetGroupMembers 获取组成员
func (s *Service) GetGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	var rels []models.Relationship
	if err := s.db.WithContext(ctx).Where("service_id = ? AND object_type = ? AND object_id = ? AND relation = ?", "system", "group", groupID, "member").
		Find(&rels).Error; err != nil {
		return nil, fmt.Errorf("获取组成员失败: %w", err)
	}

	userIDs := make([]string, 0, len(rels))
	for _, rel := range rels {
		if rel.SubjectType == "user" {
			userIDs = append(userIDs, rel.SubjectID)
		}
	}

	return userIDs, nil
}
