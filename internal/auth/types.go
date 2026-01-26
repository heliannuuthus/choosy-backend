package auth

import (
	"fmt"
	"strings"
	"time"
)

// Domain 用户域
type Domain string

const (
	DomainCIAM Domain = "ciam" // Customer Identity（C 端用户）
	DomainPIAM Domain = "piam" // Partner/Employee Identity（B 端用户）
)

// IDP 身份提供方
type IDP string

const (
	// CIAM 域
	IDPWechatMP IDP = "wechat:mp" // 微信小程序
	IDPTTMP     IDP = "tt:mp"     // 抖音小程序
	IDPAlipayMP IDP = "alipay:mp" // 支付宝小程序

	// PIAM 域
	IDPWecom  IDP = "wecom"  // 企业微信
	IDPGithub IDP = "github" // GitHub
	IDPGoogle IDP = "google" // Google
)

// GetDomain 获取 IDP 所属域
func (i IDP) GetDomain() Domain {
	switch i {
	case IDPWecom, IDPGithub, IDPGoogle:
		return DomainPIAM
	default:
		return DomainCIAM
	}
}

// SupportsAutoCreate 是否支持自动创建用户
func (i IDP) SupportsAutoCreate() bool {
	switch i {
	case IDPWechatMP, IDPTTMP, IDPAlipayMP:
		return true // C 端都支持
	default:
		return false // B 端需要预先配置
	}
}

// GrantType 授权类型
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

// CodeChallengeMethod PKCE 验证方法（OAuth2.1 只允许 S256）
type CodeChallengeMethod string

const (
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

// Scope 常量
const (
	ScopeOpenID        = "openid"         // 默认授予
	ScopeProfile       = "profile"        // 昵称、头像
	ScopeEmail         = "email"          // 邮箱
	ScopePhone         = "phone"          // 手机号
	ScopeOfflineAccess = "offline_access" // Refresh Token
)

// ============= Request/Response =============

// AuthorizeRequest 授权请求（GET 参数）
type AuthorizeRequest struct {
	ResponseType        string              `form:"response_type" binding:"required,oneof=code"` // 只允许 code
	ClientID            string              `form:"client_id" binding:"required"`
	Audience            string              `form:"audience" binding:"required"` // 目标服务 ID
	RedirectURI         string              `form:"redirect_uri" binding:"required"`
	CodeChallenge       string              `form:"code_challenge" binding:"required"`
	CodeChallengeMethod CodeChallengeMethod `form:"code_challenge_method" binding:"required,oneof=S256"` // 只允许 S256
	State               string              `form:"state"`
	Scope               string              `form:"scope"` // 空格分隔的 scope 列表
}

// ParseScopes 解析 scope 字符串为列表
func (r *AuthorizeRequest) ParseScopes() []string {
	if r.Scope == "" {
		return nil
	}
	return strings.Fields(r.Scope)
}

// IDPConfig IDP 配置信息（返回给前端）
type IDPConfig struct {
	Type          string                 `json:"type"`                     // Connection（IDP）类型
	ClientID      string                 `json:"client_id,omitempty"`      // IDP 的客户端 ID
	Capture       *CaptureConfig         `json:"capture,omitempty"`        // 人机验证配置
	AllowedScopes []string               `json:"allowed_scopes,omitempty"` // 该 connection 允许的 scopes
	Extra         map[string]interface{} `json:"extra,omitempty"`          // 其他配置信息
}

// CaptureConfig 人机验证配置
type CaptureConfig struct {
	Required bool   `json:"required"`           // 是否需要人机验证
	Type     string `json:"type,omitempty"`     // 验证类型：captcha/turnstile/hcaptcha
	SiteKey  string `json:"site_key,omitempty"` // 站点密钥（前端使用）
}

// IDPsResponse IDPs 列表响应
type IDPsResponse struct {
	IDPs []IDPConfig `json:"idps"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Connection string            `json:"connection" binding:"required"` // 身份提供方（IDP）
	Data       map[string]string `json:"data" binding:"required"`       // Connection 需要的数据
}

// LoginResponse 登录响应
type LoginResponse struct {
	Code        string `json:"code,omitempty"`         // 授权码
	RedirectURI string `json:"redirect_uri,omitempty"` // 重定向 URI
}

// InteractionRequiredResponse 需要交互的响应
type InteractionRequiredResponse struct {
	Error          string `json:"error"` // interaction_required
	ErrorDesc      string `json:"error_description,omitempty"`
	Require        string `json:"require"`                    // captcha
	CaptchaSiteKey string `json:"captcha_site_key,omitempty"` // 验证码站点密钥
}

// TokenRequest Token 请求
type TokenRequest struct {
	GrantType    GrantType `form:"grant_type" binding:"required,oneof=authorization_code refresh_token"`
	Code         string    `form:"code"`          // authorization_code 时必填
	RedirectURI  string    `form:"redirect_uri"`  // authorization_code 时必填
	ClientID     string    `form:"client_id"`     // 必填
	CodeVerifier string    `form:"code_verifier"` // PKCE 验证器
	RefreshToken string    `form:"refresh_token"` // refresh_token grant 时必填
}

// TokenResponse Token 响应
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"` // 只有 offline_access 时返回
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"` // 实际授予的 scope
}

// IntrospectRequest Token 内省请求
type IntrospectRequest struct {
	Token string `form:"token" binding:"required"`
}

// IntrospectResponse Token 内省响应
type IntrospectResponse struct {
	Active   bool   `json:"active"`
	Sub      string `json:"sub,omitempty"`
	Aud      string `json:"aud,omitempty"`
	Iss      string `json:"iss,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
	Iat      int64  `json:"iat,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

// RevokeRequest 撤销请求
type RevokeRequest struct {
	Token    string `form:"token" binding:"required"`
	ClientID string `form:"client_id"`
}

// UserInfoResponse 用户信息响应（脱敏）
type UserInfoResponse struct {
	Sub      string `json:"sub"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"` // 脱敏
	Phone    string `json:"phone,omitempty"` // 脱敏
}

// UpdateUserInfoRequest 更新用户信息请求
type UpdateUserInfoRequest struct {
	Nickname string `json:"nickname" binding:"omitempty,max=64"`
	Picture  string `json:"picture" binding:"omitempty,max=512"`
}

// ============= Error =============

// Error OAuth2 错误
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// 标准错误码
const (
	ErrInvalidRequest          = "invalid_request"
	ErrUnauthorizedClient      = "unauthorized_client"
	ErrAccessDenied            = "access_denied"
	ErrInvalidClient           = "invalid_client"
	ErrInvalidGrant            = "invalid_grant"
	ErrUnsupportedGrantType    = "unsupported_grant_type"
	ErrInvalidToken            = "invalid_token"
	ErrServerError             = "server_error"
	ErrInteractionRequired     = "interaction_required"
	ErrUnsupportedResponseType = "unsupported_response_type"
)

// NewError 创建错误
func NewError(code, description string) *Error {
	return &Error{Code: code, Description: description}
}

// ============= Internal Types =============

// Session 认证会话
type Session struct {
	ID                  string              `json:"id"`
	ClientID            string              `json:"client_id"`
	Audience            string              `json:"audience"`     // 目标服务 ID
	RedirectURI         string              `json:"redirect_uri"`
	CodeChallenge       string              `json:"code_challenge"`
	CodeChallengeMethod CodeChallengeMethod `json:"code_challenge_method"`
	State               string              `json:"state"`
	Scope               string              `json:"scope"`
	Connection          string              `json:"connection,omitempty"` // 用户选择的 connection
	CreatedAt           time.Time           `json:"created_at"`
	ExpiresAt           time.Time           `json:"expires_at"`

	// 登录后填充
	UserID       string `json:"user_id,omitempty"`
	IDP          IDP    `json:"idp,omitempty"`
	GrantedScope string `json:"granted_scope,omitempty"` // 实际授予的 scope
}

// AuthorizationCode 授权码
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	Audience            string    `json:"audience"` // 目标服务 ID
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	Scope               string    `json:"scope"` // 实际授予的 scope
	UserID              string    `json:"user_id"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used"`
}

// SubjectClaims sub 字段解密后的内容
type SubjectClaims struct {
	OpenID   string `json:"openid"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

// Identity Token 解析后的身份信息
type Identity struct {
	UserID   string    `json:"sub"`
	ClientID string    `json:"cli,omitempty"`      // 应用 ID（新版本 token）
	Audience string    `json:"aud,omitempty"`      // 服务 ID（新版本 token）
	Scope    string    `json:"scope"`
	Nickname string    `json:"nickname,omitempty"`
	Picture  string    `json:"picture,omitempty"`
	Email    string    `json:"email,omitempty"`
	Phone    string    `json:"phone,omitempty"`
	Issuer   string    `json:"iss,omitempty"`      // 签发者
	IssuedAt time.Time `json:"iat,omitempty"`      // 签发时间
	ExpireAt time.Time `json:"exp,omitempty"`      // 过期时间
}

// GetOpenID 兼容旧接口
func (i *Identity) GetOpenID() string {
	return i.UserID
}

// OpenID 兼容旧接口
func (i *Identity) OpenID() string {
	return i.UserID
}

// HasScope 检查是否包含某个 scope
func (i *Identity) HasScope(scope string) bool {
	scopes := strings.Fields(i.Scope)
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ============= Scope Helpers =============

// ParseScopes 解析 scope 字符串
func ParseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

// JoinScopes 合并 scope 列表
func JoinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// ScopeIntersection 计算 scope 交集
func ScopeIntersection(requested, allowed []string) []string {
	allowedSet := make(map[string]bool)
	for _, s := range allowed {
		allowedSet[s] = true
	}

	var result []string
	for _, s := range requested {
		if allowedSet[s] {
			result = append(result, s)
		}
	}
	return result
}

// ContainsScope 检查 scope 列表是否包含某个 scope
func ContainsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// MaskEmail 邮箱脱敏：a**@example.com
func MaskEmail(email string) string {
	if email == "" {
		return ""
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}
	local := parts[0]
	if len(local) <= 1 {
		return local + "**@" + parts[1]
	}
	return string(local[0]) + "**@" + parts[1]
}

// MaskPhone 手机号脱敏：138****1234
func MaskPhone(phone string) string {
	if phone == "" {
		return ""
	}
	if len(phone) <= 7 {
		return phone
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}
