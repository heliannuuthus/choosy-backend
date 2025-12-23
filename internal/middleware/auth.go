package middleware

import (
	"net/http"
	"strings"

	"choosy-backend/internal/auth"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware 认证中间件（可选认证）
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			c.Next()
			return
		}

		token := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			token = authorization[7:]
		}

		identity, err := auth.VerifyAccessToken(token)
		if err == nil && identity != nil {
			c.Set("user", identity)
		}

		c.Next()
	}
}

// RequireAuth 要求认证中间件
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		token := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			token = authorization[7:]
		}

		identity, err := auth.VerifyAccessToken(token)
		if err != nil || identity == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		c.Set("user", identity)
		c.Next()
	}
}
