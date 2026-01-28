package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto/v2"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
	pkgstore "github.com/heliannuuthus/helios/pkg/store"
)

// 错误定义
var (
	ErrAuthFlowNotFound     = errors.New("auth flow not found")
	ErrAuthFlowExpired      = errors.New("auth flow expired")
	ErrAuthCodeNotFound     = errors.New("authorization code not found")
	ErrAuthCodeExpired      = errors.New("authorization code expired")
	ErrAuthCodeUsed         = errors.New("authorization code already used")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrRefreshTokenRevoked  = errors.New("refresh token revoked")
	ErrUserNotFound         = errors.New("user not found")
	ErrOTPNotFound          = errors.New("otp not found")
)

// Manager 缓存管理器
// 统管所有缓存操作：本地缓存（热数据）+ Redis（分布式数据）
type Manager struct {
	// Hermes Service（获取应用/服务/域/用户数据）
	hermesSvc *hermes.Service
	userSvc   *hermes.UserService

	// 本地缓存（ristretto，用于热数据）
	domainCache      *ristretto.Cache[string, *models.DomainWithKey]
	applicationCache *ristretto.Cache[string, *models.ApplicationWithKey]
	serviceCache     *ristretto.Cache[string, *models.ServiceWithKey]
	relationCache    *ristretto.Cache[string, []models.ApplicationServiceRelation]
	userCache        *ristretto.Cache[string, *models.UserWithDecrypted]

	// Redis 客户端（用于分布式数据）
	redis pkgstore.RedisClient

	// Key 前缀
	authFlowPrefix     string
	authCodePrefix     string
	refreshTokenPrefix string
	userTokenPrefix    string
	otpPrefix          string

	// TTL 配置
	authFlowTTL time.Duration
	authCodeTTL time.Duration
}

// ManagerConfig 配置
type ManagerConfig struct {
	HermesSvc *hermes.Service
	UserSvc   *hermes.UserService
	Redis     pkgstore.RedisClient

	// 可选配置
	AuthFlowPrefix     string
	AuthCodePrefix     string
	RefreshTokenPrefix string
	UserTokenPrefix    string
	OTPPrefix          string
	AuthFlowTTL        time.Duration
	AuthCodeTTL        time.Duration
}

// NewManager 创建缓存管理器
func NewManager(cfg *ManagerConfig) *Manager {
	cm := &Manager{
		hermesSvc: cfg.HermesSvc,
		userSvc:   cfg.UserSvc,
		redis:     cfg.Redis,

		authFlowPrefix:     defaultString(cfg.AuthFlowPrefix, "auth:flow:"),
		authCodePrefix:     defaultString(cfg.AuthCodePrefix, "auth:code:"),
		refreshTokenPrefix: defaultString(cfg.RefreshTokenPrefix, "auth:rt:"),
		userTokenPrefix:    defaultString(cfg.UserTokenPrefix, "auth:user:rt:"),
		otpPrefix:          defaultString(cfg.OTPPrefix, "auth:otp:"),

		authFlowTTL: defaultDuration(cfg.AuthFlowTTL, 10*time.Minute),
		authCodeTTL: defaultDuration(cfg.AuthCodeTTL, 5*time.Minute),
	}

	// 创建本地缓存
	cm.initLocalCaches()

	return cm
}

func defaultString(val, def string) string {
	if val == "" {
		return def
	}
	return val
}

func defaultDuration(val, def time.Duration) time.Duration {
	if val == 0 {
		return def
	}
	return val
}

// initLocalCaches 初始化本地缓存
func (cm *Manager) initLocalCaches() {
	// Domain cache
	maxCost, numCounters, bufferItems := getCacheConfig("domain")
	domainCache, err := ristretto.NewCache(&ristretto.Config[string, *models.DomainWithKey]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Domain 缓存失败: %v", err)
	} else {
		cm.domainCache = domainCache
	}

	// Application cache
	maxCost, numCounters, bufferItems = getCacheConfig("application")
	applicationCache, err := ristretto.NewCache(&ristretto.Config[string, *models.ApplicationWithKey]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Application 缓存失败: %v", err)
	} else {
		cm.applicationCache = applicationCache
	}

	// Service cache
	maxCost, numCounters, bufferItems = getCacheConfig("service")
	serviceCache, err := ristretto.NewCache(&ristretto.Config[string, *models.ServiceWithKey]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Service 缓存失败: %v", err)
	} else {
		cm.serviceCache = serviceCache
	}

	// ApplicationServiceRelation cache
	maxCost, numCounters, bufferItems = getCacheConfig("application-service-relation")
	relationCache, err := ristretto.NewCache(&ristretto.Config[string, []models.ApplicationServiceRelation]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Relation 缓存失败: %v", err)
	} else {
		cm.relationCache = relationCache
	}

	// User cache
	maxCost, numCounters, bufferItems = getCacheConfig("user")
	userCache, err := ristretto.NewCache(&ristretto.Config[string, *models.UserWithDecrypted]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 User 缓存失败: %v", err)
	} else {
		cm.userCache = userCache
	}
}

// Close 关闭缓存
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
	if cm.relationCache != nil {
		cm.relationCache.Close()
	}
	if cm.userCache != nil {
		cm.userCache.Close()
	}
}

// ==================== Hermes 数据（本地缓存 + DB）====================

// GetApplication 获取应用（带缓存）
func (cm *Manager) GetApplication(ctx context.Context, appID string) (*models.ApplicationWithKey, error) {
	cacheKey := GetKeyPrefix("application") + appID

	// 尝试从缓存获取
	if cm.applicationCache != nil {
		if cached, ok := cm.applicationCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	result, err := cm.hermesSvc.GetApplicationWithKey(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.applicationCache != nil {
		ttl := GetTTL("application")
		cm.applicationCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetService 获取服务（带缓存）
func (cm *Manager) GetService(ctx context.Context, serviceID string) (*models.ServiceWithKey, error) {
	cacheKey := GetKeyPrefix("service") + serviceID

	// 尝试从缓存获取
	if cm.serviceCache != nil {
		if cached, ok := cm.serviceCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	result, err := cm.hermesSvc.GetServiceWithKey(ctx, serviceID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.serviceCache != nil {
		ttl := GetTTL("service")
		cm.serviceCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetDomain 获取域（带缓存）
func (cm *Manager) GetDomain(ctx context.Context, domainID string) (*models.DomainWithKey, error) {
	cacheKey := GetKeyPrefix("domain") + domainID

	// 尝试从缓存获取
	if cm.domainCache != nil {
		if cached, ok := cm.domainCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	result, err := cm.hermesSvc.GetDomainWithKey(ctx, domainID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.domainCache != nil {
		ttl := GetTTL("domain")
		cm.domainCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// CheckAppServiceRelation 检查应用是否有权访问服务
func (cm *Manager) CheckAppServiceRelation(ctx context.Context, appID, serviceID string) (bool, error) {
	relations, err := cm.GetAppServiceRelations(ctx, appID)
	if err != nil {
		return false, err
	}

	for _, rel := range relations {
		if rel.ServiceID == serviceID {
			return true, nil
		}
	}

	return false, nil
}

// GetAppServiceRelations 获取应用可访问的服务关系
func (cm *Manager) GetAppServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error) {
	cacheKey := GetKeyPrefix("application-service-relation") + appID

	// 尝试从缓存获取
	if cm.relationCache != nil {
		if cached, ok := cm.relationCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	relations, err := cm.hermesSvc.GetApplicationServiceRelations(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.relationCache != nil {
		ttl := GetTTL("application-service-relation")
		cm.relationCache.SetWithTTL(cacheKey, relations, 1, ttl)
	}

	return relations, nil
}

// ==================== User（本地缓存 + DB）====================

// GetUser 获取用户（带缓存）
func (cm *Manager) GetUser(ctx context.Context, openID string) (*models.UserWithDecrypted, error) {
	cacheKey := GetKeyPrefix("user") + openID

	// 尝试从缓存获取
	if cm.userCache != nil {
		if cached, ok := cm.userCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 UserService 获取
	result, err := cm.userSvc.GetUserWithDecrypted(ctx, openID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.userCache != nil {
		ttl := GetTTL("user")
		cm.userCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetUserByIdentity 根据身份获取用户（带缓存）
func (cm *Manager) GetUserByIdentity(ctx context.Context, idp, providerID string) (*models.UserWithDecrypted, error) {
	// 先从 DB 查找（身份关联不缓存）
	result, err := cm.userSvc.GetUserWithDecryptedByIdentity(ctx, idp, providerID)
	if err != nil {
		return nil, err
	}

	// 存入用户缓存
	if cm.userCache != nil {
		cacheKey := GetKeyPrefix("user") + result.OpenID
		ttl := GetTTL("user")
		cm.userCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// FindOrCreateUser 查找或创建用户
func (cm *Manager) FindOrCreateUser(ctx context.Context, req *models.FindOrCreateUserRequest) (*models.UserWithDecrypted, bool, error) {
	user, isNew, err := cm.userSvc.FindOrCreate(ctx, req)
	if err != nil {
		return nil, false, err
	}

	// 存入缓存
	if cm.userCache != nil {
		cacheKey := GetKeyPrefix("user") + user.OpenID
		ttl := GetTTL("user")
		cm.userCache.SetWithTTL(cacheKey, user, 1, ttl)
	}

	return user, isNew, nil
}

// InvalidateUser 清除用户缓存
func (cm *Manager) InvalidateUser(ctx context.Context, openID string) {
	if cm.userCache != nil {
		cacheKey := GetKeyPrefix("user") + openID
		cm.userCache.Del(cacheKey)
	}
}

// ==================== AuthFlow（Redis）====================

// AuthFlow 认证流程（简化版，详细定义在 authflow.go）
type AuthFlow struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Data      []byte    `json:"data"` // JSON 序列化的完整 AuthFlow
}

// SaveAuthFlow 保存 AuthFlow
func (cm *Manager) SaveAuthFlow(ctx context.Context, flowID string, data []byte, ttl time.Duration) error {
	if ttl == 0 {
		ttl = cm.authFlowTTL
	}
	return cm.redis.Set(ctx, cm.authFlowPrefix+flowID, string(data), ttl)
}

// GetAuthFlow 获取 AuthFlow
func (cm *Manager) GetAuthFlow(ctx context.Context, flowID string) ([]byte, error) {
	data, err := cm.redis.Get(ctx, cm.authFlowPrefix+flowID)
	if err != nil {
		return nil, ErrAuthFlowNotFound
	}
	return []byte(data), nil
}

// DeleteAuthFlow 删除 AuthFlow（设置短 TTL 让其自然过期）
func (cm *Manager) DeleteAuthFlow(ctx context.Context, flowID string) error {
	// 设置 5 秒后过期，而不是立即删除
	data, err := cm.redis.Get(ctx, cm.authFlowPrefix+flowID)
	if err != nil {
		return nil // 不存在就算了
	}
	return cm.redis.Set(ctx, cm.authFlowPrefix+flowID, data, 5*time.Second)
}

// ==================== AuthCode（Redis）====================

// AuthorizationCode 授权码
type AuthorizationCode struct {
	Code      string    `json:"code"`
	FlowID    string    `json:"flow_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// SaveAuthCode 保存授权码
func (cm *Manager) SaveAuthCode(ctx context.Context, code *AuthorizationCode) error {
	data, err := json.Marshal(code)
	if err != nil {
		return err
	}
	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		ttl = cm.authCodeTTL
	}
	return cm.redis.Set(ctx, cm.authCodePrefix+code.Code, string(data), ttl)
}

// GetAuthCode 获取授权码
func (cm *Manager) GetAuthCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	data, err := cm.redis.Get(ctx, cm.authCodePrefix+code)
	if err != nil {
		return nil, ErrAuthCodeNotFound
	}

	var authCode AuthorizationCode
	if err := json.Unmarshal([]byte(data), &authCode); err != nil {
		return nil, err
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrAuthCodeExpired
	}

	if authCode.Used {
		return nil, ErrAuthCodeUsed
	}

	return &authCode, nil
}

// MarkAuthCodeUsed 标记授权码已使用
func (cm *Manager) MarkAuthCodeUsed(ctx context.Context, code string) error {
	authCode, err := cm.GetAuthCode(ctx, code)
	if err != nil {
		return err
	}

	authCode.Used = true
	data, err := json.Marshal(authCode)
	if err != nil {
		return fmt.Errorf("marshal auth code: %w", err)
	}

	remaining := time.Until(authCode.ExpiresAt)
	if remaining <= 0 {
		remaining = time.Second
	}

	return cm.redis.Set(ctx, cm.authCodePrefix+code, string(data), remaining)
}

// ==================== OTP（Redis）====================

// SaveOTP 保存验证码
func (cm *Manager) SaveOTP(ctx context.Context, key, code string, ttl time.Duration) error {
	return cm.redis.Set(ctx, cm.otpPrefix+key, code, ttl)
}

// GetOTP 获取验证码
func (cm *Manager) GetOTP(ctx context.Context, key string) (string, error) {
	code, err := cm.redis.Get(ctx, cm.otpPrefix+key)
	if err != nil {
		return "", ErrOTPNotFound
	}
	return code, nil
}

// DeleteOTP 删除验证码
func (cm *Manager) DeleteOTP(ctx context.Context, key string) error {
	return cm.redis.Del(ctx, cm.otpPrefix+key)
}

// VerifyOTP 验证并删除验证码
func (cm *Manager) VerifyOTP(ctx context.Context, key, code string) error {
	stored, err := cm.GetOTP(ctx, key)
	if err != nil {
		return err
	}
	if stored != code {
		return fmt.Errorf("invalid otp")
	}
	return cm.DeleteOTP(ctx, key)
}

// ==================== RefreshToken（Redis）====================

// RefreshToken 刷新令牌
type RefreshToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Audience  string    `json:"audience"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

// IsValid 检查是否有效
func (r *RefreshToken) IsValid() bool {
	return !r.Revoked && time.Now().Before(r.ExpiresAt)
}

// SaveRefreshToken 保存刷新令牌
func (cm *Manager) SaveRefreshToken(ctx context.Context, token *RefreshToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Second
	}

	if err := cm.redis.Set(ctx, cm.refreshTokenPrefix+token.Token, string(data), ttl); err != nil {
		return err
	}

	// 添加到用户的 token 集合
	return cm.redis.SAdd(ctx, cm.userTokenPrefix+token.UserID, token.Token)
}

// GetRefreshToken 获取刷新令牌
func (cm *Manager) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	data, err := cm.redis.Get(ctx, cm.refreshTokenPrefix+token)
	if err != nil {
		return nil, ErrRefreshTokenNotFound
	}

	var rt RefreshToken
	if err := json.Unmarshal([]byte(data), &rt); err != nil {
		return nil, err
	}

	if time.Now().After(rt.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}

	if rt.Revoked {
		return nil, ErrRefreshTokenRevoked
	}

	return &rt, nil
}

// RevokeRefreshToken 撤销刷新令牌
func (cm *Manager) RevokeRefreshToken(ctx context.Context, token string) error {
	data, err := cm.redis.Get(ctx, cm.refreshTokenPrefix+token)
	if err != nil {
		return nil
	}

	var rt RefreshToken
	if err := json.Unmarshal([]byte(data), &rt); err != nil {
		return err
	}

	rt.Revoked = true
	newData, err := json.Marshal(rt)
	if err != nil {
		return fmt.Errorf("marshal refresh token: %w", err)
	}

	remaining := time.Until(rt.ExpiresAt)
	if remaining <= 0 {
		remaining = time.Second
	}

	return cm.redis.Set(ctx, cm.refreshTokenPrefix+token, string(newData), remaining)
}

// RevokeUserRefreshTokens 撤销用户所有刷新令牌
func (cm *Manager) RevokeUserRefreshTokens(ctx context.Context, userID string) error {
	tokens, err := cm.redis.SMembers(ctx, cm.userTokenPrefix+userID)
	if err != nil {
		return nil
	}

	for _, token := range tokens {
		if err := cm.RevokeRefreshToken(ctx, token); err != nil {
			logger.Warnf("[Manager] revoke refresh token failed: %v", err)
		}
	}

	return nil
}

// ListUserRefreshTokens 列出用户的刷新令牌
func (cm *Manager) ListUserRefreshTokens(ctx context.Context, userID, clientID string) ([]*RefreshToken, error) {
	tokens, err := cm.redis.SMembers(ctx, cm.userTokenPrefix+userID)
	if err != nil {
		return nil, nil
	}

	var result []*RefreshToken
	for _, token := range tokens {
		rt, err := cm.GetRefreshToken(ctx, token)
		if err != nil {
			continue
		}
		if clientID == "" || rt.ClientID == clientID {
			result = append(result, rt)
		}
	}

	return result, nil
}

// ==================== 辅助函数 ====================

// getCacheConfig 从全局 viper 获取指定 cache 类型的配置
func getCacheConfig(cacheType string) (maxCost int64, numCounters int64, bufferItems int64) {
	v := config.V()
	prefix := "auth.cache." + cacheType + "."

	// 默认值
	defaultMaxCost := int64(1000)
	defaultNumCounters := int64(10000)
	defaultBufferItems := int64(64)

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

	defaultPrefixes := map[string]string{
		"domain":                       "domain:",
		"application":                  "app:",
		"service":                      "svc:",
		"user":                         "user:",
		"application-service-relation": "app-svc-rel:",
	}

	if keyPrefix := v.GetString(prefix + "key-prefix"); keyPrefix != "" {
		return keyPrefix
	}

	if defaultPrefix, ok := defaultPrefixes[cacheType]; ok {
		return defaultPrefix
	}

	return cacheType + ":"
}
