package middleware

import (
	"net/http"
	"strings"

	"github.com/heliannuuthus/helios/internal/auth"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/token"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware 认证中间件（可选认证，旧版兼容）
func AuthMiddleware() gin.HandlerFunc {
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

		identity, err := auth.VerifyAccessToken(tokenStr)
		if err == nil && identity != nil {
			logger.Infof("[Auth] 可选认证成功 - Path: %s, OpenID: %s", c.Request.URL.Path, identity.OpenID)
			c.Set("user", identity)
		}

		c.Next()
	}
}

// RequireAuth 要求认证中间件（旧版兼容）
func RequireAuth() gin.HandlerFunc {
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

		identity, err := auth.VerifyAccessToken(tokenStr)
		if err != nil || identity == nil {
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

// tokenPreview 生成 token 预览（避免在日志中暴露完整 token）
func tokenPreview(tokenStr string, length int) string {
	if len(tokenStr) <= length {
		return tokenStr
	}
	return tokenStr[:length]
}

// RequireToken 新版本认证中间件（使用 token.Verifier）
func RequireToken(v *token.Verifier) gin.HandlerFunc {
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

		identity, err := v.Verify(c.Request.Context(), tokenStr)
		if err != nil {
			logger.Warnf("[Auth] Token 验证失败 - Path: %s, IP: %s, Error: %v, TokenPreview: %s...",
				c.Request.URL.Path,
				c.ClientIP(),
				err,
				tokenPreview(tokenStr, 20))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		logger.Infof("[Auth] 认证成功 - Path: %s, UserID: %s", c.Request.URL.Path, identity.UserID)
		c.Set("user", identity)
		c.Next()
	}
}

// OptionalToken 新版本可选认证中间件（使用 token.Verifier）
func OptionalToken(v *token.Verifier) gin.HandlerFunc {
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

		identity, err := v.Verify(c.Request.Context(), tokenStr)
		if err == nil && identity != nil {
			logger.Infof("[Auth] 可选认证成功 - Path: %s, UserID: %s", c.Request.URL.Path, identity.UserID)
			c.Set("user", identity)
		}

		c.Next()
	}
}
