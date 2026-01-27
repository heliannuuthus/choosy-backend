package auth

import (
	"net/http"
	"strings"

	"github.com/heliannuuthus/helios/internal/auth/token"

	"github.com/gin-gonic/gin"
)

// Middleware 认证中间件（用于验证 CAT/ServiceJWT）
type Middleware struct {
	issuer *token.Issuer
}

// NewMiddleware 创建中间件
func NewMiddleware(issuer *token.Issuer) *Middleware {
	return &Middleware{issuer: issuer}
}

// RequireClientAuth 要求客户端认证（验证 CAT）
func (m *Middleware) RequireClientAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := m.extractToken(c)
		if tokenStr == "" {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, Error{
				Code:        ErrInvalidToken,
				Description: "missing client access token",
			})
			return
		}

		// 验证 ClientAccessToken
		claims, err := m.issuer.VerifyClientAccessToken(c.Request.Context(), tokenStr)
		if err != nil {
			c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			c.AbortWithStatusJSON(http.StatusUnauthorized, Error{
				Code:        ErrInvalidToken,
				Description: err.Error(),
			})
			return
		}

		c.Set("client_claims", claims)
		c.Next()
	}
}

// RequireServiceAuth 要求服务认证（验证 ServiceJWT）
func (m *Middleware) RequireServiceAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := m.extractToken(c)
		if tokenStr == "" {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, Error{
				Code:        ErrInvalidToken,
				Description: "missing service jwt",
			})
			return
		}

		// 验证 ServiceJWT
		claims, err := m.issuer.VerifyServiceJWT(c.Request.Context(), tokenStr)
		if err != nil {
			c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			c.AbortWithStatusJSON(http.StatusUnauthorized, Error{
				Code:        ErrInvalidToken,
				Description: err.Error(),
			})
			return
		}

		c.Set("service_claims", claims)
		c.Next()
	}
}

func (m *Middleware) extractToken(c *gin.Context) string {
	// 从 Authorization header
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// GetClientClaims 从上下文获取客户端信息
func GetClientClaims(c *gin.Context) *token.ClientAccessTokenClaims {
	if claims, exists := c.Get("client_claims"); exists {
		return claims.(*token.ClientAccessTokenClaims)
	}
	return nil
}

// GetServiceClaims 从上下文获取服务信息
func GetServiceClaims(c *gin.Context) *token.ClientAccessTokenClaims {
	if claims, exists := c.Get("service_claims"); exists {
		return claims.(*token.ClientAccessTokenClaims)
	}
	return nil
}

// ============= 以下是兼容旧接口的代码，已废弃 =============

// GetIdentity 从上下文获取用户身份（兼容旧接口）
// Deprecated: auth 模块不再验证 UAT/SAT，请使用 pkg/token/Interpreter
func GetIdentity(c *gin.Context) *token.Identity {
	if identity, exists := c.Get("identity"); exists {
		return identity.(*token.Identity)
	}
	return nil
}

// GetUserID 从上下文获取用户 ID（兼容旧接口）
// Deprecated: auth 模块不再验证 UAT/SAT
func GetUserID(c *gin.Context) string {
	if identity := GetIdentity(c); identity != nil {
		return identity.OpenID
	}
	return ""
}

// GetDomain 从上下文获取域（兼容旧接口）
// Deprecated: Domain 信息已从 Token 中移除
func GetDomain(c *gin.Context) Domain {
	return ""
}
