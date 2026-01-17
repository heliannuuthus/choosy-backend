package handlers

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"choosy-backend/internal/auth"
	"choosy-backend/internal/config"
	"choosy-backend/internal/kms"
	"choosy-backend/internal/logger"
	"choosy-backend/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

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

func generateRandomNickname() string {
	adj := adjectives[rand.Intn(len(adjectives))]
	noun := nouns[rand.Intn(len(nouns))]
	return adj + noun
}

func generateRandomAvatar(seed string) string {
	return fmt.Sprintf("https://api.dicebear.com/7.x/fun-emoji/svg?seed=%s", url.QueryEscape(seed))
}

// AuthHandler 认证处理器
type AuthHandler struct {
	db      *gorm.DB
	service *auth.Service
}

// NewAuthHandler 创建认证处理器
func NewAuthHandler(db *gorm.DB) *AuthHandler {
	return &AuthHandler{
		db:      db,
		service: auth.NewService(db),
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
	Nickname     string `form:"nickname"`
	Avatar       string `form:"avatar"`
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

func (h *AuthHandler) handleAuthorizationCode(c *gin.Context, code, nickname, avatar string) {
	if code == "" {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: "code is required for authorization_code grant",
		})
		return
	}

	// 解析 code，格式：idp:actual_code，如 wechat:mp:xxx 或 tt:mp:xxx
	// 所有平台都必须显式指定 idp，不区分对待
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
	if idp != auth.IDPWechatMP && idp != auth.IDPTTMP && idp != auth.IDPAlipayMP {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "unsupported_idp",
			ErrorDescription: fmt.Sprintf("不支持的平台: %s，支持的平台: %s, %s, %s", idp, auth.IDPWechatMP, auth.IDPTTMP, auth.IDPAlipayMP),
		})
		return
	}

	var tokens *auth.TokenPair

	switch idp {
	case auth.IDPWechatMP:
		appid := config.GetString("idps.wxmp.appid")
		secret := config.GetString("idps.wxmp.secret")
		if appid == "" || secret == "" {
			logger.Error("微信配置缺失: idps.wxmp.appid 或 idps.wxmp.secret 未设置")
			c.JSON(http.StatusInternalServerError, OAuth2Error{
				Error:            "server_error",
				ErrorDescription: "微信小程序配置缺失",
			})
			return
		}

		wxResult, err := h.service.WxCode2Session(actualCode)
		if err != nil {
			logger.Errorf("微信登录失败: %v", err)
			c.JSON(http.StatusBadRequest, OAuth2Error{
				Error:            "invalid_grant",
				ErrorDescription: err.Error(),
			})
			return
		}

		if nickname == "" {
			nickname = generateRandomNickname()
		}
		if avatar == "" {
			avatar = generateRandomAvatar(wxResult.OpenID)
		}

		tokens, err = h.service.GenerateToken(wxResult, nickname, avatar)
		if err != nil {
			logger.Errorf("生成 token 失败: %v", err)
			c.JSON(http.StatusInternalServerError, OAuth2Error{
				Error:            "server_error",
				ErrorDescription: "生成 token 失败",
			})
			return
		}

	case auth.IDPTTMP:
		appid := config.GetString("idps.tt.appid")
		secret := config.GetString("idps.tt.secret")
		if appid == "" || secret == "" {
			logger.Error("TT 配置缺失: idps.tt.appid 或 idps.tt.secret 未设置")
			c.JSON(http.StatusInternalServerError, OAuth2Error{
				Error:            "server_error",
				ErrorDescription: "TT 小程序配置缺失",
			})
			return
		}

		ttResult, err := h.service.TtCode2Session(actualCode)
		if err != nil {
			logger.Errorf("TT 登录失败: %v", err)
			c.JSON(http.StatusBadRequest, OAuth2Error{
				Error:            "invalid_grant",
				ErrorDescription: err.Error(),
			})
			return
		}

		if nickname == "" {
			nickname = generateRandomNickname()
		}
		if avatar == "" {
			avatar = generateRandomAvatar(ttResult.OpenID)
		}

		tokens, err = h.service.GenerateTokenFromTt(ttResult, nickname, avatar)
		if err != nil {
			logger.Errorf("生成 token 失败: %v", err)
			c.JSON(http.StatusInternalServerError, OAuth2Error{
				Error:            "server_error",
				ErrorDescription: "生成 token 失败",
			})
			return
		}

	case auth.IDPAlipayMP:
		appid := config.GetString("idps.alipay.appid")
		secret := config.GetString("idps.alipay.secret")
		if appid == "" || secret == "" {
			logger.Error("支付宝配置缺失: idps.alipay.appid 或 idps.alipay.secret 未设置")
			c.JSON(http.StatusInternalServerError, OAuth2Error{
				Error:            "server_error",
				ErrorDescription: "支付宝小程序配置缺失",
			})
			return
		}

		alipayResult, err := h.service.AlipayCode2Session(actualCode)
		if err != nil {
			logger.Errorf("支付宝登录失败: %v", err)
			c.JSON(http.StatusBadRequest, OAuth2Error{
				Error:            "invalid_grant",
				ErrorDescription: err.Error(),
			})
			return
		}

		if nickname == "" {
			nickname = generateRandomNickname()
		}
		if avatar == "" {
			avatar = generateRandomAvatar(alipayResult.OpenID)
		}

		tokens, err = h.service.GenerateTokenFromAlipay(alipayResult, nickname, avatar)
		if err != nil {
			logger.Errorf("生成 token 失败: %v", err)
			c.JSON(http.StatusInternalServerError, OAuth2Error{
				Error:            "server_error",
				ErrorDescription: "生成 token 失败",
			})
			return
		}

	default:
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "unsupported_idp",
			ErrorDescription: fmt.Sprintf("不支持的平台: %s", idp),
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

func (h *AuthHandler) handleRefreshToken(c *gin.Context, refreshToken string) {
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, OAuth2Error{
			Error:            "invalid_request",
			ErrorDescription: "refresh_token is required for refresh_token grant",
		})
		return
	}

	// refresh 时默认使用 wechat:mp（后续可从请求头或其他方式获取）
	idp := auth.IDPWechatMP

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
// @Router /api/profile [get]
func (h *AuthHandler) Profile(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*auth.Identity)

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
	// 解密手机号并脱敏
	if dbUser.EncryptedPhone != nil && *dbUser.EncryptedPhone != "" {
		if phone, err := kms.DecryptPhone(*dbUser.EncryptedPhone, dbUser.OpenID); err == nil {
			profile.Phone = kms.MaskPhone(phone)
		}
	}

	c.JSON(http.StatusOK, profile)
}

type UpdateProfileRequest struct {
	Nickname  string  `json:"nickname" binding:"omitempty,max=64"`
	Avatar    string  `json:"avatar" binding:"omitempty,max=512"` // 移除 url 验证，允许临时路径或 OSS URL
	Gender    *int8   `json:"gender" binding:"omitempty,oneof=0 1 2"`
	PhoneCode *string `json:"phone_code" binding:"omitempty"` // 小程序授权码，用于绑定手机号；传空字符串表示解绑，不传则不处理
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
// @Router /api/profile [put]
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*auth.Identity)

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
		// Avatar 字段现在应该已经是 OSS URL（由前端上传接口返回）
		// 直接保存即可
		updates["avatar"] = req.Avatar
	}
	if req.Gender != nil {
		updates["gender"] = *req.Gender
	}

	// 处理手机号绑定/解绑
	// phone_code 不为 nil 时处理：空字符串表示解绑，非空表示绑定/更新
	if req.PhoneCode != nil {
		if *req.PhoneCode == "" {
			// phone_code 为空字符串，表示解绑手机号
			if dbUser.Phone != nil && *dbUser.Phone != "" {
				updates["phone"] = nil
				updates["encrypted_phone"] = nil
				logger.Infof("[Auth] 手机号解绑成功 - OpenID: %s", identity.GetOpenID())
			}
		} else {
			// 从 Token aud 解析 idp（暂时使用默认值，后续可以从 UserIdentity 表查询）
			idp := h.getIDPFromContext(c)
			if idp == "" {
				idp = auth.IDPWechatMP // 默认微信
			}

			// 获取手机号
			provider, err := auth.GetPhoneProvider(idp)
			if err != nil {
				logger.Errorf("[Auth] 获取手机号提供方失败 - IDP: %s, Error: %v", idp, err)
				c.JSON(http.StatusBadRequest, OAuth2Error{
					Error:            "unsupported_platform",
					ErrorDescription: err.Error(),
				})
				return
			}

			phone, err := provider.GetPhoneNumber(*req.PhoneCode)
			if err != nil {
				logger.Errorf("[Auth] 获取手机号失败 - OpenID: %s, Error: %v", identity.GetOpenID(), err)
				c.JSON(http.StatusBadRequest, OAuth2Error{
					Error:            "phone_fetch_failed",
					ErrorDescription: "获取手机号失败，请重试",
				})
				return
			}

			// 计算手机号哈希（用于查询）
			phoneHash := kms.Hash(phone)

			// 检查手机号是否已被其他用户绑定（全局不允许重复）
			var existingUser models.User
			if err := h.db.Where("phone = ? AND openid != ?", phoneHash, identity.GetOpenID()).First(&existingUser).Error; err == nil {
				c.JSON(http.StatusConflict, OAuth2Error{
					Error:            "phone_bound",
					ErrorDescription: "该手机号已绑定其他账号",
				})
				return
			}

			// 加密手机号（用于展示）
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
	}

	if len(updates) > 0 {
		if err := h.db.Model(&dbUser).Updates(updates).Error; err != nil {
			logger.Errorf("更新用户资料失败 - OpenID: %s, Error: %v", identity.GetOpenID(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "更新失败"})
			return
		}
		logger.Infof("[Auth] 用户资料更新成功 - OpenID: %s, Updates: %v", identity.GetOpenID(), updates)
	}

	// 重新查询以返回最新数据
	h.db.First(&dbUser, "openid = ?", identity.GetOpenID())

	profile := UserProfile{
		OpenID:   dbUser.OpenID,
		Nickname: dbUser.Nickname,
		Avatar:   dbUser.Avatar,
		Gender:   dbUser.Gender,
	}
	// 解密手机号并脱敏
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
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*auth.Identity)
	count := h.service.RevokeAllTokens(identity.GetOpenID())

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("已登出所有设备，共撤销 %d 个会话", count)})
}

// StatsResponse 统计数据响应
type StatsResponse struct {
	Favorites int64 `json:"favorites"` // 收藏数
	History   int64 `json:"history"`   // 浏览历史数
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
func (h *AuthHandler) GetStats(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*auth.Identity)
	openID := identity.GetOpenID()

	// 查询收藏数
	var favoritesCount int64
	if err := h.db.Model(&models.Favorite{}).Where("openid = ?", openID).Count(&favoritesCount).Error; err != nil {
		logger.Errorf("[Auth] 查询收藏数失败 - OpenID: %s, Error: %v", openID, err)
		favoritesCount = 0
	}

	// 查询浏览历史数
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

// getIDPFromContext 从请求上下文获取 idp
func (h *AuthHandler) getIDPFromContext(c *gin.Context) string {
	// 从 Token 的 aud 解析
	// aud 格式: issuer:provider:namespace，如 choosy:wechat:mp
	if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		token := authHeader
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		}
		if identity, err := auth.VerifyAccessToken(token); err == nil {
			_ = identity // Token 验证成功，但 Identity 里没有 aud
			// TODO: 如果需要从 Token 获取 aud，需要修改 VerifyAccessToken 返回 aud
		}
	}
	// 暂时默认返回微信
	return auth.IDPWechatMP
}
