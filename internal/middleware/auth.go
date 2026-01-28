package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/pkg/auth/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// AuthMiddleware 认证中间件（可选认证）
// Deprecated: 使用 OptionalToken 替代
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Warnf("[Auth] AuthMiddleware is deprecated, use OptionalToken instead")
		c.Next()
	}
}

// RequireAuth 要求认证中间件
// Deprecated: 使用 RequireToken 替代
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Warnf("[Auth] RequireAuth is deprecated, use RequireToken instead")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "deprecated middleware"})
	}
}

// tokenPreview 生成 token 预览（避免在日志中暴露完整 token）
func tokenPreview(tokenStr string, length int) string {
	if len(tokenStr) <= length {
		return tokenStr
	}
	return tokenStr[:length]
}

// RequireToken 新版本认证中间件（使用 token.Interpreter）
func RequireToken(v *token.Interpreter) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			logger.Debugf("[Auth] 请求未携带 Authorization 头 - Path: %s, IP: %s", c.Request.URL.Path, c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		tokenStr := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			tokenStr = authorization[7:]
		}

		identity, err := v.Interpret(c.Request.Context(), tokenStr)
		if err != nil {
			logger.Warnf("[Auth] Token 验证失败 - Path: %s, IP: %s, Error: %v, TokenPreview: %s...",
				c.Request.URL.Path,
				c.ClientIP(),
				err,
				tokenPreview(tokenStr, 20))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		logger.Infof("[Auth] 认证成功 - Path: %s, OpenID: %s", c.Request.URL.Path, identity.OpenID)
		c.Set("user", identity)
		c.Next()
	}
}

// OptionalToken 新版本可选认证中间件（使用 token.Interpreter）
func OptionalToken(v *token.Interpreter) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			c.Next()
			return
		}

		tokenStr := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			tokenStr = authorization[7:]
		}

		identity, err := v.Interpret(c.Request.Context(), tokenStr)
		if err == nil && identity != nil {
			logger.Infof("[Auth] 可选认证成功 - Path: %s, OpenID: %s", c.Request.URL.Path, identity.OpenID)
			c.Set("user", identity)
		}

		c.Next()
	}
}
