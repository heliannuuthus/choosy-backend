package auth

import (
	"fmt"
	"net/http"
	"strings"

	"zwei-backend/internal/idp/alipay"
	"zwei-backend/internal/idp/tt"
	"zwei-backend/internal/idp/wechat"
	"zwei-backend/internal/kms"
	"zwei-backend/internal/logger"
	"zwei-backend/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Handler 认证处理器
type Handler struct {
	db      *gorm.DB
	service *Service
}

// NewHandler 创建认证处理器
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		db:      db,
		service: NewService(db),
	}
}

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required,oneof=authorization_code refresh_token"`
	Code         string `form:"code"` // 格式：idp:code，如 wechat:mp:xxx 或 tt:mp:xxx
	RefreshToken string `form:"refresh_token"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

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
// @Failure 412 {object} OAuth2Error "refresh_token 无效或已过期"
// @Failure 500 {object} OAuth2Error
// @Router /api/token [post]
func (h *Handler) Token(c *gin.Context) {
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
		h.handleAuthorizationCode(c, req.Code)
	case GrantTypeRefreshToken:
		h.handleRefreshToken(c, req.RefreshToken)
	default:
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "unsupported_grant_type",
			ErrorDescription: "grant_type must be authorization_code or refresh_token",
		})
	}
}

func (h *Handler) handleAuthorizationCode(c *gin.Context, code string) {
	if code == "" {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: "code is required for authorization_code grant",
		})
		return
	}

	// 解析 code，格式：idp:actual_code，如 wechat:mp:xxx 或 tt:mp:xxx
	parts := strings.SplitN(code, ":", 3)
	if len(parts) < 3 {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: "code format must be idp:actual_code (e.g., wechat:mp:xxx, tt:mp:xxx)",
		})
		return
	}

	idp := parts[0] + ":" + parts[1]
	actualCode := parts[2]

	// 验证 idp 是否支持
	if idp != IDPWechatMP && idp != IDPTTMP && idp != IDPAlipayMP {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "unsupported_idp",
			ErrorDescription: fmt.Sprintf("不支持的平台: %s，支持的平台: %s, %s, %s", idp, IDPWechatMP, IDPTTMP, IDPAlipayMP),
		})
		return
	}

	// 统一调用 Service.Login 处理登录流程
	tokens, err := h.service.Login(idp, actualCode)
	if err != nil {
		logger.Errorf("登录失败: %v", err)
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_grant",
			ErrorDescription: err.Error(),
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

func (h *Handler) handleRefreshToken(c *gin.Context, refreshToken string) {
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: "refresh_token is required for refresh_token grant",
		})
		return
	}

	idp := IDPWechatMP

	tokens, err := h.service.RefreshToken(refreshToken, idp)
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

type RevokeRequest struct {
	Token string `form:"token" binding:"required"`
}

// Revoke 撤销 token
// @Summary 撤销 token
// @Tags auth
// @Accept x-www-form-urlencoded
// @Produce json
// @Param token formData string true "要撤销的 refresh_token"
// @Success 200 {object} map[string]string
// @Failure 400 {object} OAuth2Error
// @Router /api/revoke [post]
func (h *Handler) Revoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		})
		return
	}

	h.service.RevokeToken(req.Token)
	c.JSON(http.StatusOK, gin.H{"message": "已撤销"})
}

type UserProfile struct {
	OpenID   string `json:"openid"`
	Nickname string `json:"nickname,omitempty"`
	Avatar   string `json:"avatar,omitempty"`
	Gender   int8   `json:"gender"`
	Phone    string `json:"phone,omitempty"`
}

// Profile 获取当前用户信息
// @Summary 获取当前用户信息
// @Tags auth
// @Produce json
// @Security Bearer
// @Success 200 {object} UserProfile
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/user/profile [get]
func (h *Handler) Profile(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*Identity)

	var dbUser models.User
	if err := h.db.Where("openid = ?", identity.GetOpenID()).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "用户不存在"})
		return
	}

	profile := UserProfile{
		OpenID:   dbUser.OpenID,
		Nickname: dbUser.Nickname,
		Avatar:   dbUser.Avatar,
		Gender:   dbUser.Gender,
	}
	if dbUser.EncryptedPhone != nil && *dbUser.EncryptedPhone != "" {
		if phone, err := kms.DecryptPhone(*dbUser.EncryptedPhone, dbUser.OpenID); err == nil {
			profile.Phone = kms.MaskPhone(phone)
		}
	}

	c.JSON(http.StatusOK, profile)
}

type UpdateProfileRequest struct {
	Nickname string `json:"nickname" binding:"omitempty,max=64"`
	Avatar   string `json:"avatar" binding:"omitempty,max=512"`
	Gender   *int8  `json:"gender" binding:"omitempty,oneof=0 1 2"`
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
// @Router /api/user/profile [put]
func (h *Handler) UpdateProfile(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*Identity)

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	var dbUser models.User
	if err := h.db.Where("openid = ?", identity.GetOpenID()).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "用户不存在"})
		return
	}

	updates := make(map[string]interface{})
	if req.Nickname != "" {
		updates["nickname"] = req.Nickname
	}
	if req.Avatar != "" {
		updates["avatar"] = req.Avatar
	}
	if req.Gender != nil {
		updates["gender"] = *req.Gender
	}

	if len(updates) > 0 {
		if err := h.db.Model(&dbUser).Updates(updates).Error; err != nil {
			logger.Errorf("更新用户资料失败 - OpenID: %s, Error: %v", identity.GetOpenID(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "更新失败"})
			return
		}
		logger.Infof("[Auth] 用户资料更新成功 - OpenID: %s, Updates: %v", identity.GetOpenID(), updates)
	}

	h.db.First(&dbUser, "openid = ?", identity.GetOpenID())

	profile := UserProfile{
		OpenID:   dbUser.OpenID,
		Nickname: dbUser.Nickname,
		Avatar:   dbUser.Avatar,
		Gender:   dbUser.Gender,
	}
	if dbUser.EncryptedPhone != nil && *dbUser.EncryptedPhone != "" {
		if phone, err := kms.DecryptPhone(*dbUser.EncryptedPhone, dbUser.OpenID); err == nil {
			profile.Phone = kms.MaskPhone(phone)
		}
	}

	c.JSON(http.StatusOK, profile)
}

// LogoutAll 登出所有设备
// @Summary 登出所有设备
// @Tags auth
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/revoke-all [post]
func (h *Handler) LogoutAll(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*Identity)
	count := h.service.RevokeAllTokens(identity.GetOpenID())

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("已登出所有设备，共撤销 %d 个会话", count)})
}

// StatsResponse 统计数据响应
type StatsResponse struct {
	Favorites int64 `json:"favorites"`
	History   int64 `json:"history"`
}

// GetStats 获取用户统计数据（收藏数、浏览历史数）
// @Summary 获取用户统计数据
// @Description 获取当前用户的收藏数和浏览历史数
// @Tags auth
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} StatsResponse
// @Failure 401 {object} map[string]string
// @Router /api/stats [get]
func (h *Handler) GetStats(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*Identity)
	openID := identity.GetOpenID()

	var favoritesCount int64
	if err := h.db.Model(&models.Favorite{}).Where("openid = ?", openID).Count(&favoritesCount).Error; err != nil {
		logger.Errorf("[Auth] 查询收藏数失败 - OpenID: %s, Error: %v", openID, err)
		favoritesCount = 0
	}

	var historyCount int64
	if err := h.db.Model(&models.ViewHistory{}).Where("openid = ?", openID).Count(&historyCount).Error; err != nil {
		logger.Errorf("[Auth] 查询浏览历史数失败 - OpenID: %s, Error: %v", openID, err)
		historyCount = 0
	}

	c.JSON(http.StatusOK, StatsResponse{
		Favorites: favoritesCount,
		History:   historyCount,
	})
}

type IdpProfileRequest struct {
	PhoneCode string `json:"phone_code"`
}

// IdpProfile 更新平台相关用户信息（根据不同的 idp 做不同的数据处理）
// @Summary 更新平台相关用户信息
// @Tags auth
// @Accept json
// @Produce json
// @Security Bearer
// @Param idp path string true "身份提供方" Enums(wechat:mp, tt:mp, alipay:mp)
// @Param request body IdpProfileRequest true "更新请求"
// @Success 200 {object} UserProfile
// @Failure 400 {object} OAuth2Error
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/{idp}/profile [post]
func (h *Handler) IdpProfile(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*Identity)
	idpParam := c.Param("idp")

	validIDPs := map[string]bool{
		IDPWechatMP: true,
		IDPTTMP:     true,
		IDPAlipayMP: true,
	}
	if !validIDPs[idpParam] {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_idp",
			ErrorDescription: fmt.Sprintf("不支持的平台: %s", idpParam),
		})
		return
	}

	var req IdpProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		})
		return
	}

	var dbUser models.User
	if err := h.db.Where("openid = ?", identity.GetOpenID()).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "用户不存在"})
		return
	}

	updates := make(map[string]interface{})

	if req.PhoneCode == "" {
		if dbUser.Phone != nil && *dbUser.Phone != "" {
			updates["phone"] = nil
			updates["encrypted_phone"] = nil
			logger.Infof("[Auth] 手机号解绑成功 - OpenID: %s", identity.GetOpenID())
		}
	} else {
		var phone string
		var err error

		switch idpParam {
		case IDPWechatMP:
			client := wechat.NewClient()
			phone, err = client.GetPhoneNumber(req.PhoneCode)
		case IDPTTMP:
			client := tt.NewClient()
			phone, err = client.GetPhoneNumber(req.PhoneCode)
		case IDPAlipayMP:
			client := alipay.NewClient()
			phone, err = client.GetPhoneNumber(req.PhoneCode)
		default:
			c.JSON(http.StatusBadRequest, OAuth2Error{
				Error:            "unsupported_platform",
				ErrorDescription: fmt.Sprintf("不支持的平台: %s", idpParam),
			})
			return
		}

		if err != nil {
			logger.Errorf("[Auth] 获取手机号失败 - OpenID: %s, Error: %v", identity.GetOpenID(), err)
			c.JSON(http.StatusBadRequest, OAuth2Error{
				Error:            "phone_fetch_failed",
				ErrorDescription: "获取手机号失败，请重试",
			})
			return
		}

		phoneHash := kms.Hash(phone)

		var existingUser models.User
		if err := h.db.Where("phone = ? AND openid != ?", phoneHash, identity.GetOpenID()).First(&existingUser).Error; err == nil {
			c.JSON(http.StatusConflict, OAuth2Error{
				Error:            "phone_bound",
				ErrorDescription: "该手机号已绑定其他账号",
			})
			return
		}

		encryptedPhone, err := kms.EncryptPhone(phone, identity.GetOpenID())
		if err != nil {
			logger.Errorf("[Auth] 加密手机号失败 - OpenID: %s, Error: %v", identity.GetOpenID(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "绑定失败"})
			return
		}

		updates["phone"] = phoneHash
		updates["encrypted_phone"] = encryptedPhone

		logger.Infof("[Auth] 手机号绑定成功 - OpenID: %s, Phone: %s",
			identity.GetOpenID(), kms.MaskPhone(phone))
	}

	if len(updates) > 0 {
		if err := h.db.Model(&dbUser).Updates(updates).Error; err != nil {
			logger.Errorf("更新用户手机号失败 - OpenID: %s, Error: %v", identity.GetOpenID(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "更新失败"})
			return
		}
		logger.Infof("[Auth] 用户手机号更新成功 - OpenID: %s, Updates: %v", identity.GetOpenID(), updates)
	}

	h.db.First(&dbUser, "openid = ?", identity.GetOpenID())

	profile := UserProfile{
		OpenID:   dbUser.OpenID,
		Nickname: dbUser.Nickname,
		Avatar:   dbUser.Avatar,
		Gender:   dbUser.Gender,
	}
	if dbUser.EncryptedPhone != nil && *dbUser.EncryptedPhone != "" {
		if phone, err := kms.DecryptPhone(*dbUser.EncryptedPhone, dbUser.OpenID); err == nil {
			profile.Phone = kms.MaskPhone(phone)
		}
	}

	c.JSON(http.StatusOK, profile)
}
