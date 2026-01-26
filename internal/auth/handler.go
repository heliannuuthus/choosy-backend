package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/heliannuuthus/helios/internal/config"
)

// Handler 认证处理器
type Handler struct {
	service *Service
}

// NewHandler 创建认证处理器
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// Authorize GET /auth/authorize
// @Summary 创建认证会话并重定向到登录页面
// @Description OAuth2.1/OIDC 授权端点，创建认证会话，设置 auth-session Cookie，然后重定向到登录页面
// Session ID 通过 HttpOnly Cookie（auth-session）传递，后续 login 请求会从 Cookie 读取。
// 如果 SPA 和 API 不在同一域名，需要配置 CORS allow_credentials=true。
// @Tags auth
// @Param response_type query string true "响应类型，必须为 code" Enums(code)
// @Param client_id query string true "客户端 ID"
// @Param redirect_uri query string true "重定向 URI"
// @Param code_challenge query string true "PKCE Code Challenge"
// @Param code_challenge_method query string true "PKCE 方法，必须为 S256" Enums(S256)
// @Param state query string false "状态参数"
// @Param scope query string false "授权范围"
// @Success 302 "重定向到登录页面"
// @Failure 400 {object} Error
// @Router /auth/authorize [get]
func (h *Handler) Authorize(c *gin.Context) {
	var req AuthorizeRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	sessionID, err := h.service.Authorize(c.Request.Context(), &req)
	if err != nil {
		if authErr, ok := err.(*Error); ok {
			h.errorResponse(c, http.StatusBadRequest, authErr)
		} else {
			h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		}
		return
	}

	// 设置 session cookie（HttpOnly，必须通过 Cookie 传递）
	// Cookie 名称使用 auth-session（带连字符，符合 HTTP Cookie 规范）
	// HttpOnly 防止 JavaScript 访问，提高安全性
	c.SetCookie("auth-session", sessionID, 600, "/", "", false, true)

	// 重定向到登录页面（前端登录页面）
	// 前端可以从 GET /idps?client_id=xxx 获取可用的认证源配置
	loginURL := "/login"
	c.Redirect(http.StatusFound, loginURL)
}

// Login POST /auth/login
// @Summary 认证登录
// @Description 使用 connection（IDP）和对应的 data 完成登录，返回授权码。
// Session ID 必须从 Cookie（auth_session）获取，如果没有 Cookie 则视为无效 session。
// SPA 场景使用 HttpOnly Cookie，浏览器会自动发送，更安全。
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "登录请求"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} Error
// @Failure 412 {object} Error "Session 过期"
// @Router /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	// 只能从 cookie 获取 session_id（使用 auth-session）
	sessionID, err := c.Cookie("auth-session")
	if err != nil || sessionID == "" {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, "missing session_id (auth-session cookie required)"))
		return
	}

	resp, err := h.service.Login(c.Request.Context(), sessionID, &req)
	if err != nil {
		if authErr, ok := err.(*Error); ok {
			// Session 过期返回 412
			if authErr.Code == ErrInvalidRequest {
				// 检查错误描述是否包含 session expired
				if authErr.Description == "session not found or expired" {
					h.errorResponse(c, http.StatusPreconditionFailed, authErr)
					return
				}
			}
			h.errorResponse(c, http.StatusBadRequest, authErr)
		} else {
			h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		}
		return
	}

	// 如果有前置认证需求（如人机验证），返回 interaction_required 错误
	if strings.HasPrefix(resp.Code, "require:") {
		require := strings.TrimPrefix(resp.Code, "require:")
		// 获取 capture 配置
		idp := IDP(req.Connection)
		var captureSiteKey string
		switch idp {
		case IDPWechatMP:
			captureSiteKey = config.GetString("idps.wxmp.capture.site_key")
		case IDPTTMP:
			captureSiteKey = config.GetString("idps.tt.capture.site_key")
		case IDPAlipayMP:
			captureSiteKey = config.GetString("idps.alipay.capture.site_key")
		}

		c.JSON(http.StatusOK, InteractionRequiredResponse{
			Error:          ErrInteractionRequired,
			ErrorDesc:      "Human verification required",
			Require:        require,
			CaptchaSiteKey: captureSiteKey,
		})
		return
	}

	// 清除 session cookie（如果存在）
	c.SetCookie("auth-session", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, resp)
}

// Token POST /auth/token
// @Summary 获取 Token
// @Description OAuth2 Token 端点
// @Tags auth
// @Accept x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "授权类型" Enums(authorization_code,refresh_token)
// @Param code formData string false "授权码"
// @Param redirect_uri formData string false "重定向 URI"
// @Param client_id formData string true "客户端 ID"
// @Param code_verifier formData string false "PKCE 验证器"
// @Param refresh_token formData string false "Refresh Token"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} Error
// @Router /auth/token [post]
func (h *Handler) Token(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	resp, err := h.service.ExchangeToken(c.Request.Context(), &req)
	if err != nil {
		if authErr, ok := err.(*Error); ok {
			h.errorResponse(c, http.StatusBadRequest, authErr)
		} else {
			h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Revoke POST /auth/revoke
// @Summary 撤销 Token
// @Description 撤销 Refresh Token
// @Tags auth
// @Accept x-www-form-urlencoded
// @Produce json
// @Param token formData string true "Token"
// @Success 200
// @Router /auth/revoke [post]
func (h *Handler) Revoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	// RFC 7009: 即使 token 无效，也应返回 200
	_ = h.service.RevokeToken(c.Request.Context(), req.Token)
	c.Status(http.StatusOK)
}

// Logout POST /auth/logout
// @Summary 登出
// @Description 撤销用户所有 Token
// @Tags auth
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} Error
// @Router /auth/logout [post]
func (h *Handler) Logout(c *gin.Context) {
	identity := GetIdentity(c)
	if identity == nil {
		h.errorResponse(c, http.StatusUnauthorized, NewError(ErrInvalidToken, "not authenticated"))
		return
	}

	if err := h.service.RevokeAllTokens(c.Request.Context(), identity.UserID); err != nil {
		h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, "failed to revoke tokens"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// UserInfo GET /auth/userinfo
// @Summary 获取用户信息
// @Description 根据 Token 的 scope 返回用户信息（敏感信息脱敏）
// @Tags auth
// @Produce json
// @Security Bearer
// @Success 200 {object} UserInfoResponse
// @Failure 401 {object} Error
// @Router /auth/userinfo [get]
func (h *Handler) UserInfo(c *gin.Context) {
	identity := GetIdentity(c)
	if identity == nil {
		h.errorResponse(c, http.StatusUnauthorized, NewError(ErrInvalidToken, "not authenticated"))
		return
	}

	resp, err := h.service.GetUserInfo(identity)
	if err != nil {
		h.errorResponse(c, http.StatusNotFound, NewError(ErrServerError, "user not found"))
		return
	}

	c.JSON(http.StatusOK, resp)
}

// UpdateUserInfo PUT /auth/userinfo
// @Summary 更新用户信息
// @Description 更新当前用户信息
// @Tags auth
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body UpdateUserInfoRequest true "更新请求"
// @Success 200 {object} UserInfoResponse
// @Failure 400 {object} Error
// @Failure 401 {object} Error
// @Router /auth/userinfo [put]
func (h *Handler) UpdateUserInfo(c *gin.Context) {
	identity := GetIdentity(c)
	if identity == nil {
		h.errorResponse(c, http.StatusUnauthorized, NewError(ErrInvalidToken, "not authenticated"))
		return
	}

	var req UpdateUserInfoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	resp, err := h.service.UpdateUserInfo(identity, &req)
	if err != nil {
		h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		return
	}

	c.JSON(http.StatusOK, resp)
}

// IDPs GET /idps
// @Summary 获取认证源配置
// @Description 根据 client_id 获取可用的认证源（Connection）配置，包括 Capture 配置
// @Tags auth
// @Param client_id query string true "客户端 ID"
// @Success 200 {object} IDPsResponse
// @Failure 400 {object} Error
// @Router /idps [get]
func (h *Handler) IDPs(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, "client_id is required"))
		return
	}

	resp, err := h.service.GetIDPConfigs(clientID)
	if err != nil {
		if authErr, ok := err.(*Error); ok {
			h.errorResponse(c, http.StatusBadRequest, authErr)
		} else {
			h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Introspect POST /auth/introspect
// @Summary Token 内省
// @Description 验证 Token 并返回完整元数据（需要 Service JWT 认证）
// @Tags auth
// @Accept x-www-form-urlencoded
// @Produce json
// @Security Bearer
// @Param token formData string true "Access Token"
// @Success 200 {object} IntrospectResponse
// @Failure 401 {object} Error
// @Router /auth/introspect [post]
func (h *Handler) Introspect(c *gin.Context) {
	// 1. 获取 Service JWT
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		h.errorResponse(c, http.StatusUnauthorized, NewError(ErrInvalidClient, "missing service jwt"))
		return
	}
	serviceJWT := authHeader[7:]

	// 2. 获取 Token
	var req IntrospectRequest
	if err := c.ShouldBind(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	// 3. 调用服务
	resp, err := h.service.Introspect(c.Request.Context(), req.Token, serviceJWT)
	if err != nil {
		if authErr, ok := err.(*Error); ok {
			h.errorResponse(c, http.StatusUnauthorized, authErr)
		} else {
			h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *Handler) errorResponse(c *gin.Context, status int, err *Error) {
	c.JSON(status, err)
}

// JWKS GET /.well-known/jwks.json
// @Summary 获取 JWKS（JSON Web Key Set）
// @Description 根据 client_id 返回其所属域的公钥，用于验证 JWT 签名
// @Tags auth
// @Param client_id query string true "客户端 ID"
// @Success 200 {object} map[string]interface{} "JWKS 格式的公钥列表"
// @Failure 400 {object} Error
// @Failure 404 {object} Error
// @Router /.well-known/jwks.json [get]
func (h *Handler) JWKS(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, "client_id is required"))
		return
	}

	// 获取 JWKS
	jwks, err := h.service.GetJWKS(c.Request.Context(), clientID)
	if err != nil {
		if authErr, ok := err.(*Error); ok {
			h.errorResponse(c, http.StatusNotFound, authErr)
		} else {
			h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		}
		return
	}

	c.JSON(http.StatusOK, jwks)
}
