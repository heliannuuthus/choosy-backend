package handlers

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"

	"choosy-backend/internal/config"
	"choosy-backend/internal/logger"
	"choosy-backend/internal/models"
	"choosy-backend/internal/services"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 随机昵称词库
var (
	adjectives = []string{
		"快乐的", "开心的", "可爱的", "勤劳的", "聪明的", "活泼的", "温柔的", "勇敢的",
		"神秘的", "优雅的", "淘气的", "机灵的", "呆萌的", "傲娇的", "高冷的", "佛系的",
	}
	nouns = []string{
		"小猫", "小狗", "兔子", "熊猫", "狐狸", "松鼠", "考拉", "企鹅",
		"海豚", "独角兽", "小龙", "凤凰", "麒麟", "仙鹤", "锦鲤", "萌新",
	}
)

// generateRandomNickname 生成随机昵称
func generateRandomNickname() string {
	adj := adjectives[rand.Intn(len(adjectives))]
	noun := nouns[rand.Intn(len(nouns))]
	return adj + noun
}

// generateRandomAvatar 生成随机头像 URL（使用 DiceBear API）
func generateRandomAvatar(seed string) string {
	// 使用 openid 作为 seed 保证同一用户头像一致
	return fmt.Sprintf("https://api.dicebear.com/7.x/fun-emoji/svg?seed=%s", url.QueryEscape(seed))
}

// AuthHandler 认证处理器
type AuthHandler struct {
	db      *gorm.DB
	service *services.AuthService
}

// NewAuthHandler 创建认证处理器
func NewAuthHandler(db *gorm.DB) *AuthHandler {
	return &AuthHandler{
		db:      db,
		service: services.NewAuthService(db),
	}
}

// OAuth2 grant types
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

// TokenRequest OAuth2.1 风格的 token 请求（form-urlencoded）
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required,oneof=authorization_code refresh_token"`
	Code         string `form:"code"`          // grant_type=authorization_code 时必填
	RefreshToken string `form:"refresh_token"` // grant_type=refresh_token 时必填
	Nickname     string `form:"nickname"`      // 可选，用户昵称
	Avatar       string `form:"avatar"`        // 可选，用户头像 URL
}

// TokenResponse token 响应
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// OAuth2Error OAuth2 错误响应
type OAuth2Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Token OAuth2.1 风格的 token 端点
// @Summary 获取/刷新 token
// @Description 支持 authorization_code（微信登录）和 refresh_token 两种 grant_type
// @Tags auth
// @Accept x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "授权类型" Enums(authorization_code, refresh_token)
// @Param code formData string false "微信登录 code（grant_type=authorization_code 时必填）"
// @Param refresh_token formData string false "刷新令牌（grant_type=refresh_token 时必填）"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} OAuth2Error
// @Failure 401 {object} OAuth2Error
// @Failure 500 {object} OAuth2Error
// @Router /api/auth/token [post]
func (h *AuthHandler) Token(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		})
		return
	}

	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		h.handleAuthorizationCode(c, req.Code, req.Nickname, req.Avatar)
	case GrantTypeRefreshToken:
		h.handleRefreshToken(c, req.RefreshToken)
	default:
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "unsupported_grant_type",
			ErrorDescription: "grant_type must be authorization_code or refresh_token",
		})
	}
}

// handleAuthorizationCode 处理微信登录
func (h *AuthHandler) handleAuthorizationCode(c *gin.Context, code, nickname, avatar string) {
	if code == "" {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: "code is required for authorization_code grant",
		})
		return
	}

	appid := config.GetString("idps.wxmp.appid")
	secret := config.GetString("idps.wxmp.secret")
	if appid == "" || secret == "" {
		logger.Error("微信配置缺失: idps.wxmp.appid 或 idps.wxmp.secret 未设置")
		c.JSON(http.StatusInternalServerError, OAuth2Error{
			Error:            "server_error",
			ErrorDescription: "服务器配置错误",
		})
		return
	}

	// 调用微信接口
	wxResult, err := h.service.WxCode2Session(code)
	if err != nil {
		logger.Errorf("微信登录失败: %v", err)
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_grant",
			ErrorDescription: err.Error(),
		})
		return
	}

	// 静默登录时生成随机头像和昵称
	if nickname == "" {
		nickname = generateRandomNickname()
	}
	if avatar == "" {
		avatar = generateRandomAvatar(wxResult.OpenID)
	}

	// 生成 token（包含用户信息）
	tokens, err := h.service.GenerateToken(wxResult.OpenID, nickname, avatar)
	if err != nil {
		logger.Errorf("生成 token 失败: %v", err)
		c.JSON(http.StatusInternalServerError, OAuth2Error{
			Error:            "server_error",
			ErrorDescription: "生成 token 失败",
		})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
	})
}

// handleRefreshToken 处理 token 刷新
func (h *AuthHandler) handleRefreshToken(c *gin.Context, refreshToken string) {
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: "refresh_token is required for refresh_token grant",
		})
		return
	}

	tokens, err := h.service.RefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, OAuth2Error{
			Error:            "invalid_grant",
			ErrorDescription: "refresh_token 无效或已过期",
		})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
	})
}

// RevokeRequest token 撤销请求（form-urlencoded）
type RevokeRequest struct {
	Token string `form:"token" binding:"required"`
}

// Revoke 撤销 token（OAuth2 revocation endpoint）
// @Summary 撤销 token
// @Tags auth
// @Accept x-www-form-urlencoded
// @Produce json
// @Param token formData string true "要撤销的 refresh_token"
// @Success 200 {object} map[string]string
// @Failure 400 {object} OAuth2Error
// @Router /api/auth/revoke [post]
func (h *AuthHandler) Revoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		})
		return
	}

	h.service.RevokeToken(req.Token)
	// OAuth2 revocation 规范：无论成功与否都返回 200
	c.JSON(http.StatusOK, gin.H{"message": "已撤销"})
}

// UserProfile 用户信息响应
type UserProfile struct {
	OpenID   string `json:"openid"`             // 系统生成的唯一标识（对外 ID）
	Nickname string `json:"nickname,omitempty"` // 昵称
	Avatar   string `json:"avatar,omitempty"`   // 头像
}

// Profile 获取当前用户信息
// @Summary 获取当前用户信息
// @Tags auth
// @Produce json
// @Security Bearer
// @Success 200 {object} UserProfile
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/auth/profile [get]
func (h *AuthHandler) Profile(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*services.UserIdentity)

	// 从数据库查询最新用户信息
	var dbUser models.User
	if err := h.db.Where("openid = ?", identity.GetOpenID()).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "用户不存在"})
		return
	}

	c.JSON(http.StatusOK, UserProfile{
		OpenID:   dbUser.OpenID,
		Nickname: dbUser.Nickname,
		Avatar:   dbUser.Avatar,
	})
}

// UpdateProfileRequest 更新用户信息请求
type UpdateProfileRequest struct {
	Nickname string `json:"nickname" binding:"omitempty,max=64"`
	Avatar   string `json:"avatar" binding:"omitempty,url,max=512"`
}

// UpdateProfile 更新当前用户信息
// @Summary 更新当前用户信息
// @Tags auth
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body UpdateProfileRequest true "更新请求"
// @Success 200 {object} UserProfile
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/auth/profile [put]
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*services.UserIdentity)

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	// 查找用户
	var dbUser models.User
	if err := h.db.Where("openid = ?", identity.GetOpenID()).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "用户不存在"})
		return
	}

	// 更新非空字段
	updates := make(map[string]interface{})
	if req.Nickname != "" {
		updates["nickname"] = req.Nickname
	}
	if req.Avatar != "" {
		updates["avatar"] = req.Avatar
	}

	if len(updates) > 0 {
		if err := h.db.Model(&dbUser).Updates(updates).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "更新失败"})
			return
		}
	}

	// 重新查询返回最新数据
	h.db.First(&dbUser, "openid = ?", identity.GetOpenID())

	c.JSON(http.StatusOK, UserProfile{
		OpenID:   dbUser.OpenID,
		Nickname: dbUser.Nickname,
		Avatar:   dbUser.Avatar,
	})
}

// LogoutAll 登出所有设备
// @Summary 登出所有设备
// @Tags auth
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/auth/logout-all [post]
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	// 从上下文获取用户信息
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*services.UserIdentity)
	count := h.service.RevokeAllTokens(identity.GetOpenID())

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("已登出所有设备，共撤销 %d 个会话", count)})
}
