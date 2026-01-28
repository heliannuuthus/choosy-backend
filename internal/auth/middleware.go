package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/auth/token"
)

// Middleware 认证中间件（用于验证 CAT/ServiceJWT）
type Middleware struct {
	tokenSvc *token.Service
}

// NewMiddleware 创建中间件
func NewMiddleware(tokenSvc *token.Service) *Middleware {
	return &Middleware{tokenSvc: tokenSvc}
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

		// 验证 CAT
		claims, err := m.tokenSvc.VerifyCAT(c.Request.Context(), tokenStr)
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

func (*Middleware) extractToken(c *gin.Context) string {
	// 从 Authorization header
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// GetClientClaims 从上下文获取客户端信息
func GetClientClaims(c *gin.Context) *token.CATClaims {
	if claims, exists := c.Get("client_claims"); exists {
		if catClaims, ok := claims.(*token.CATClaims); ok {
			return catClaims
		}
	}
	return nil
}
