package auth

import (
	"net/http"
	"strings"

	"github.com/heliannuuthus/helios/internal/auth/token"

	"github.com/gin-gonic/gin"
)

// Middleware 认证中间件
type Middleware struct {
	issuer *token.Issuer
}

// NewMiddleware 创建中间件
func NewMiddleware(issuer *token.Issuer) *Middleware {
	return &Middleware{issuer: issuer}
}

// RequireAuth 要求认证
func (m *Middleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, Error{
				Code:        ErrInvalidToken,
				Description: "missing access token",
			})
			return
		}

		// 验证 Access Token（统一使用 access_token）
		identity, err := m.issuer.VerifyAccessToken(token)
		if err != nil {
			c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			c.AbortWithStatusJSON(http.StatusUnauthorized, Error{
				Code:        ErrInvalidToken,
				Description: err.Error(),
			})
			return
		}

		c.Set("identity", identity)
		c.Next()
	}
}

// OptionalAuth 可选认证
func (m *Middleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			c.Next()
			return
		}

		// 验证 Access Token
		identity, err := m.issuer.VerifyAccessToken(token)
		if err == nil && identity != nil {
			c.Set("identity", identity)
		}

		c.Next()
	}
}

// RequireDomain 要求特定域
func (m *Middleware) RequireDomain(domain Domain) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity := GetIdentity(c)
		if identity == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, Error{
				Code:        ErrInvalidToken,
				Description: "authentication required",
			})
			return
		}

		// Domain 检查已移除（不再在 Token 中存储 domain）
		// 如果需要域检查，可以通过其他方式实现

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

// GetIdentity 从上下文获取用户身份
func GetIdentity(c *gin.Context) *token.Identity {
	if identity, exists := c.Get("identity"); exists {
		return identity.(*token.Identity)
	}
	return nil
}

// GetUserID 从上下文获取用户 ID
func GetUserID(c *gin.Context) string {
	if identity := GetIdentity(c); identity != nil {
		return identity.UserID
	}
	return ""
}

// GetDomain 从上下文获取域（已废弃，Token 中不再存储 domain）
func GetDomain(c *gin.Context) Domain {
	// Domain 信息已从 Token 中移除
	// 如需获取用户域，请从数据库查询
	return ""
}
