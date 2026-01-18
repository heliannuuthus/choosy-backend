package middleware

import (
	"zwei-backend/internal/config"

	"github.com/gin-gonic/gin"
)

const (
	wildcard               = "*"
	defaultAllowMethods    = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
	defaultAllowHeaders    = "Content-Type, Authorization, X-Requested-With"
	defaultMaxAge          = "86400"
	headerOrigin           = "Origin"
	headerAllowOrigin      = "Access-Control-Allow-Origin"
	headerAllowMethods     = "Access-Control-Allow-Methods"
	headerAllowHeaders     = "Access-Control-Allow-Headers"
	headerAllowCredentials = "Access-Control-Allow-Credentials"
	headerMaxAge           = "Access-Control-Max-Age"
)

// CORS 中间件
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader(headerOrigin)
		origins := config.GetStringSlice("cors.origins")

		// 检查 origin 是否在允许列表中
		allowAll := false
		allowed := false
		for _, o := range origins {
			if o == wildcard {
				allowAll = true
				break
			}
			if o == origin {
				allowed = true
				break
			}
		}

		// 设置 Access-Control-Allow-Origin
		// 注意：使用 credentials 时不能用 "*"，必须返回具体 origin
		if origin != "" && (allowAll || allowed) {
			c.Header(headerAllowOrigin, origin)
		}

		// 允许的方法
		methods := defaultAllowMethods
		allowMethods := config.GetStringSlice("cors.allow_methods")
		if len(allowMethods) > 0 && allowMethods[0] != wildcard {
			methods = ""
			for i, m := range allowMethods {
				if i > 0 {
					methods += ", "
				}
				methods += m
			}
		}
		c.Header(headerAllowMethods, methods)

		// 允许的头
		headers := defaultAllowHeaders
		allowHeaders := config.GetStringSlice("cors.allow_headers")
		if len(allowHeaders) > 0 && allowHeaders[0] != wildcard {
			headers = ""
			for i, h := range allowHeaders {
				if i > 0 {
					headers += ", "
				}
				headers += h
			}
		}
		c.Header(headerAllowHeaders, headers)

		// 允许携带凭证
		if config.GetBool("cors.allow_credentials") {
			c.Header(headerAllowCredentials, "true")
		}

		// 预检请求缓存时间
		c.Header(headerMaxAge, defaultMaxAge)

		// 处理预检请求
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
