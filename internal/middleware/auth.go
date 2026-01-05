package middleware

import (
	"net/http"
	"strings"

	"choosy-backend/internal/auth"
	"choosy-backend/internal/logger"

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
			logger.Infof("[Auth] 可选认证成功 - OpenID: %s, Path: %s", identity.OpenID, c.Request.URL.Path)
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
			logger.Warnf("[Auth] 请求未携带 Authorization 头 - Path: %s, IP: %s", c.Request.URL.Path, c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		token := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			token = authorization[7:]
		}

		identity, err := auth.VerifyAccessToken(token)
		if err != nil || identity == nil {
			logger.Warnf("[Auth] Token 验证失败 - Path: %s, IP: %s, Error: %v, TokenPreview: %s...",
				c.Request.URL.Path,
				c.ClientIP(),
				err,
				tokenPreview(token, 20))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		logger.Infof("[Auth] 认证成功 - OpenID: %s, Path: %s", identity.OpenID, c.Request.URL.Path)
		c.Set("user", identity)
		c.Next()
	}
}

// tokenPreview 生成 token 预览（避免在日志中暴露完整 token）
func tokenPreview(token string, length int) string {
	if len(token) <= length {
		return token
	}
	return token[:length]
}
