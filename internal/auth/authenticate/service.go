package authenticate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/internal/auth/cache"
	"github.com/heliannuuthus/helios/internal/auth/idp"
	"github.com/heliannuuthus/helios/internal/auth/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// 错误定义
var (
	ErrFlowNotFound       = errors.New("auth flow not found")
	ErrFlowExpired        = errors.New("auth flow expired")
	ErrFlowStateInvalid   = errors.New("auth flow state invalid")
	ErrUnsupportedAuth    = errors.New("unsupported authentication type")
	ErrConnectionNotFound = errors.New("connection not found in flow")
)

// Service 认证服务
// 管理 AuthFlow，不连接数据库
type Service struct {
	cache          *cache.Manager
	idpRegistry    *idp.Registry
	authenticators []Authenticator

	// 配置
	flowTTL time.Duration
}

// ServiceConfig 服务配置
type ServiceConfig struct {
	Cache       *cache.Manager
	IDPRegistry *idp.Registry
	EmailSender EmailSender
	FlowTTL     time.Duration
}

// NewService 创建认证服务
func NewService(cfg *ServiceConfig) *Service {
	flowTTL := cfg.FlowTTL
	if flowTTL == 0 {
		flowTTL = 10 * time.Minute
	}

	s := &Service{
		cache:       cfg.Cache,
		idpRegistry: cfg.IDPRegistry,
		flowTTL:     flowTTL,
	}

	// 注册认证器
	s.authenticators = []Authenticator{
		NewIDPAuthenticator(cfg.IDPRegistry),
		NewEmailAuthenticator(cfg.Cache, cfg.EmailSender),
	}

	return s
}

// ==================== AuthFlow 管理 ====================

// CreateFlow 创建认证流程
func (s *Service) CreateFlow(ctx context.Context, req *types.AuthRequest) (*types.AuthFlow, error) {
	// 1. 验证 response_type
	if req.ResponseType != "code" {
		return nil, errors.New("response_type must be 'code'")
	}

	// 2. 获取 Application
	app, err := s.cache.GetApplication(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("application not found: %w", err)
	}

	// 3. 验证重定向 URI
	if !app.ValidateRedirectURI(req.RedirectURI) {
		return nil, errors.New("invalid redirect_uri")
	}

	// 4. 获取 Service
	svc, err := s.cache.GetService(ctx, req.Audience)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}

	// 5. 验证 Application-Service 关系
	hasRelation, err := s.cache.CheckAppServiceRelation(ctx, req.ClientID, req.Audience)
	if err != nil {
		return nil, fmt.Errorf("check relation failed: %w", err)
	}
	if !hasRelation {
		return nil, fmt.Errorf("application %s has no access to service %s", req.ClientID, req.Audience)
	}

	// 6. 创建 AuthFlow
	flow := types.NewAuthFlow(req, s.flowTTL)
	flow.Application = app
	flow.Service = svc

	// 7. 构建 ConnectionMap
	flow.ConnectionMap = s.buildConnectionMap(app.DomainID)

	// 8. 保存到缓存
	if err := s.SaveFlow(ctx, flow); err != nil {
		return nil, fmt.Errorf("save flow failed: %w", err)
	}

	logger.Infof("[Authenticate] 创建认证流程 - FlowID: %s, ClientID: %s", flow.ID, req.ClientID)

	return flow, nil
}

// GetAndValidateFlow 获取并验证 AuthFlow
func (s *Service) GetAndValidateFlow(ctx context.Context, flowID string) (*types.AuthFlow, error) {
	flow, err := s.GetFlow(ctx, flowID)
	if err != nil {
		return nil, err
	}

	if flow.IsExpired() {
		return nil, ErrFlowExpired
	}

	return flow, nil
}

// GetFlow 获取 AuthFlow
func (s *Service) GetFlow(ctx context.Context, flowID string) (*types.AuthFlow, error) {
	data, err := s.cache.GetAuthFlow(ctx, flowID)
	if err != nil {
		return nil, ErrFlowNotFound
	}

	var flow types.AuthFlow
	if err := json.Unmarshal(data, &flow); err != nil {
		return nil, fmt.Errorf("unmarshal flow failed: %w", err)
	}

	return &flow, nil
}

// SaveFlow 保存 AuthFlow
func (s *Service) SaveFlow(ctx context.Context, flow *types.AuthFlow) error {
	data, err := json.Marshal(flow)
	if err != nil {
		return fmt.Errorf("marshal flow failed: %w", err)
	}

	ttl := time.Until(flow.ExpiresAt)
	if ttl <= 0 {
		ttl = s.flowTTL
	}

	return s.cache.SaveAuthFlow(ctx, flow.ID, data, ttl)
}

// DeleteFlow 删除 AuthFlow（设置短 TTL）
func (s *Service) DeleteFlow(ctx context.Context, flowID string) error {
	return s.cache.DeleteAuthFlow(ctx, flowID)
}

// ==================== 认证 ====================

// Authenticate 执行认证
func (s *Service) Authenticate(ctx context.Context, flow *types.AuthFlow, connection string, data map[string]any) (*AuthResult, error) {
	// 1. 验证 flow 状态
	if !flow.CanAuthenticate() {
		return nil, ErrFlowStateInvalid
	}

	// 2. 验证 connection 是否在 ConnectionMap 中
	if _, ok := flow.ConnectionMap[connection]; !ok {
		return nil, ErrConnectionNotFound
	}

	// 3. 选择认证器
	var authenticator Authenticator
	for _, auth := range s.authenticators {
		if auth.Supports(connection) {
			authenticator = auth
			break
		}
	}
	if authenticator == nil {
		return nil, ErrUnsupportedAuth
	}

	// 4. 执行认证
	result, err := authenticator.Authenticate(ctx, connection, data)
	if err != nil {
		return nil, err
	}

	logger.Infof("[Authenticate] 认证成功 - FlowID: %s, Connection: %s, ProviderID: %s", flow.ID, connection, result.ProviderID)

	return result, nil
}

// GetAvailableConnections 获取可用的 Connection（从 flow.ConnectionMap）
func (s *Service) GetAvailableConnections(flow *types.AuthFlow) []*types.ConnectionConfig {
	if flow.ConnectionMap == nil {
		return nil
	}

	configs := make([]*types.ConnectionConfig, 0, len(flow.ConnectionMap))
	for _, cfg := range flow.ConnectionMap {
		configs = append(configs, cfg)
	}
	return configs
}

// SendEmailCode 发送邮箱验证码
func (s *Service) SendEmailCode(ctx context.Context, email string) error {
	for _, auth := range s.authenticators {
		if emailAuth, ok := auth.(*EmailAuthenticator); ok {
			return emailAuth.SendCode(ctx, email)
		}
	}
	return errors.New("email authenticator not configured")
}

// ==================== 辅助方法 ====================

// buildConnectionMap 构建 ConnectionMap
func (s *Service) buildConnectionMap(domainID string) map[string]*types.ConnectionConfig {
	connectionMap := make(map[string]*types.ConnectionConfig)

	// 根据域确定可用的 IDP
	var idpTypes []string
	switch domainID {
	case "ciam":
		idpTypes = []string{idp.TypeWechatMP, idp.TypeTTMP, idp.TypeAlipayMP}
	case "piam":
		idpTypes = []string{idp.TypeWecom, idp.TypeGithub, idp.TypeGoogle}
	default:
		idpTypes = []string{idp.TypeWechatMP, idp.TypeTTMP, idp.TypeAlipayMP}
	}

	// 从配置读取每个 IDP 的配置
	for _, idpType := range idpTypes {
		if !s.idpRegistry.Has(idpType) {
			continue
		}

		cfg := s.getConnectionConfig(idpType)
		if cfg != nil {
			connectionMap[idpType] = cfg
		}
	}

	// 添加邮箱验证码（如果配置了）
	if config.GetBool("idps.email.enabled") {
		connectionMap["email"] = &types.ConnectionConfig{
			Type:          "email",
			Name:          "邮箱验证码",
			AllowedScopes: config.GetStringSlice("idps.email.allowed_scopes"),
		}
	}

	return connectionMap
}

// getConnectionConfig 获取 Connection 配置
func (s *Service) getConnectionConfig(idpType string) *types.ConnectionConfig {
	var configPrefix string
	var name string

	switch idpType {
	case idp.TypeWechatMP:
		configPrefix = "idps.wxmp"
		name = "微信小程序"
	case idp.TypeTTMP:
		configPrefix = "idps.tt"
		name = "抖音小程序"
	case idp.TypeAlipayMP:
		configPrefix = "idps.alipay"
		name = "支付宝小程序"
	case idp.TypeWecom:
		configPrefix = "idps.wecom"
		name = "企业微信"
	case idp.TypeGithub:
		configPrefix = "idps.github"
		name = "GitHub"
	case idp.TypeGoogle:
		configPrefix = "idps.google"
		name = "Google"
	default:
		return nil
	}

	appID := config.GetString(configPrefix + ".appid")
	if appID == "" {
		return nil
	}

	cfg := &types.ConnectionConfig{
		Type:          idpType,
		Name:          name,
		ClientID:      appID,
		AllowedScopes: config.GetStringSlice(configPrefix + ".allowed_scopes"),
	}

	// 人机验证配置
	if config.GetBool(configPrefix + ".capture.required") {
		cfg.Capture = &types.CaptureConfig{
			Required: true,
			Type:     config.GetString(configPrefix + ".capture.type"),
			SiteKey:  config.GetString(configPrefix + ".capture.site_key"),
		}
	}

	return cfg
}
