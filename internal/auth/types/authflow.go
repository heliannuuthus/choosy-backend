package types

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// FlowState 认证流程状态
type FlowState string

const (
	FlowStateInitialized   FlowState = "initialized"   // 已初始化
	FlowStateAuthenticated FlowState = "authenticated" // 已认证（用户已验证）
	FlowStateAuthorized    FlowState = "authorized"    // 已授权（权限已计算）
	FlowStateCompleted     FlowState = "completed"     // 已完成（授权码已生成）
)

// AuthFlow 认证流程上下文
// auth session = flowID
type AuthFlow struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	State     FlowState `json:"state"`

	// 请求参数
	Request *AuthRequest `json:"request"`

	// 实体信息（认证过程中填充）
	Application *models.ApplicationWithKey `json:"application,omitempty"`
	Service     *models.ServiceWithKey     `json:"service,omitempty"`
	User        *models.UserWithDecrypted  `json:"user,omitempty"`

	// Connection 配置
	ConnectionMap map[string]*ConnectionConfig `json:"connection_map,omitempty"` // 所有可用的 Connection 配置
	Connection    string                       `json:"connection,omitempty"`     // 当前使用的 Connection（已认证则不可回退）

	// 认证结果
	ProviderID string `json:"provider_id,omitempty"` // 认证源侧用户标识
	IsNewUser  bool   `json:"is_new_user,omitempty"` // 是否新用户

	// 授权结果
	GrantedScopes []string `json:"granted_scopes,omitempty"`
}

// AuthRequest 认证请求参数
type AuthRequest struct {
	// OAuth2 标准参数
	ResponseType        string `json:"response_type" form:"response_type" binding:"required,oneof=code"`
	ClientID            string `json:"client_id" form:"client_id" binding:"required"`
	Audience            string `json:"audience" form:"audience" binding:"required"`
	RedirectURI         string `json:"redirect_uri" form:"redirect_uri" binding:"required"`
	CodeChallenge       string `json:"code_challenge" form:"code_challenge" binding:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" form:"code_challenge_method" binding:"required,oneof=S256"`
	State               string `json:"state,omitempty" form:"state"`
	Scope               string `json:"scope,omitempty" form:"scope"`

	// 扩展参数
	Params map[string]any `json:"params,omitempty"`
}

// ParseScopes 解析 scope 字符串为列表
func (r *AuthRequest) ParseScopes() []string {
	if r.Scope == "" {
		return nil
	}
	scopes := make([]string, 0)
	for _, s := range splitScopes(r.Scope) {
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// splitScopes 按空格分割 scope
func splitScopes(scope string) []string {
	var result []string
	current := ""
	for _, c := range scope {
		if c == ' ' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// AuthorizationCode 授权码
type AuthorizationCode struct {
	Code      string    `json:"code"`
	FlowID    string    `json:"flow_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// ConnectionConfig Connection 配置
type ConnectionConfig struct {
	Type          string                 `json:"type"`                     // wechat:mp, tt:mp, email 等
	Name          string                 `json:"name,omitempty"`           // 显示名称
	ClientID      string                 `json:"client_id,omitempty"`      // IDP 的 AppID
	AllowedScopes []string               `json:"allowed_scopes,omitempty"` // 允许的 scope
	Capture       *CaptureConfig         `json:"capture,omitempty"`        // 人机验证配置
	Extra         map[string]interface{} `json:"extra,omitempty"`          // 其他配置
}

// CaptureConfig 人机验证配置
type CaptureConfig struct {
	Required bool   `json:"required"`
	Type     string `json:"type,omitempty"`
	SiteKey  string `json:"site_key,omitempty"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Connection string         `json:"connection" binding:"required"` // 身份提供方（IDP）
	Data       map[string]any `json:"data" binding:"required"`       // Connection 需要的数据
}

// ==================== 辅助函数 ====================

// GenerateFlowID 生成 Flow ID
func GenerateFlowID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return "flow_" + hex.EncodeToString(bytes)
}

// GenerateAuthorizationCode 生成授权码
func GenerateAuthorizationCode() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// NewAuthFlow 创建新的 AuthFlow
func NewAuthFlow(req *AuthRequest, ttl time.Duration) *AuthFlow {
	now := time.Now()
	return &AuthFlow{
		ID:        GenerateFlowID(),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		State:     FlowStateInitialized,
		Request:   req,
	}
}

// IsExpired 检查是否已过期
func (f *AuthFlow) IsExpired() bool {
	return time.Now().After(f.ExpiresAt)
}

// CanAuthenticate 检查是否可以进行认证
func (f *AuthFlow) CanAuthenticate() bool {
	return f.State == FlowStateInitialized && !f.IsExpired()
}

// CanAuthorize 检查是否可以进行授权
func (f *AuthFlow) CanAuthorize() bool {
	return f.State == FlowStateAuthenticated && !f.IsExpired()
}

// SetAuthenticated 设置为已认证状态
func (f *AuthFlow) SetAuthenticated(connection, providerID string, user *models.UserWithDecrypted, isNewUser bool) {
	f.State = FlowStateAuthenticated
	f.Connection = connection
	f.ProviderID = providerID
	f.User = user
	f.IsNewUser = isNewUser
}

// SetAuthorized 设置为已授权状态
func (f *AuthFlow) SetAuthorized(grantedScopes []string) {
	f.State = FlowStateAuthorized
	f.GrantedScopes = grantedScopes
}

// SetCompleted 设置为已完成状态
func (f *AuthFlow) SetCompleted() {
	f.State = FlowStateCompleted
}
