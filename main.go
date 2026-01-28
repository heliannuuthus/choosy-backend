package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/heliannuuthus/helios/docs" // swagger docs
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/middleware"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/oss"
)

// @title Helios API
// @version 1.0
// @description Helios 统一后端 API - 提供认证、业务和身份与访问管理服务

// @host localhost:18000
// @BasePath /api

// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @description 输入 "Bearer {token}"

func main() {
	// 加载配置
	config.Load()

	// 初始化日志
	logger.InitWithConfig(logger.Config{
		Format: config.GetString("log.format"),
		Level:  config.GetString("log.level"),
		Debug:  config.GetBool("app.debug"),
	})
	defer logger.Sync()

	// 初始化 OSS（如果配置了）
	if config.GetString("oss.endpoint") != "" {
		if err := oss.Init(); err != nil {
			logger.Warnf("OSS 初始化失败（将跳过图片上传功能）: %v", err)
		} else {
			// 初始化 STS（如果配置了）
			if config.GetString("oss.role-arn") != "" {
				if err := oss.InitSTS(); err != nil {
					logger.Warnf("OSS STS 初始化失败（将使用主账号凭证）: %v", err)
				}
			}
		}
	}

	// 通过 Wire 初始化应用
	app, err := InitializeApp()
	if err != nil {
		logger.Fatalf("初始化应用失败: %v", err)
	}

	// 设置 Gin 模式
	if !config.GetBool("app.debug") {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建 Gin 引擎
	r := gin.Default()
	r.RedirectTrailingSlash = false

	// 添加中间件
	r.Use(middleware.CORS())

	// 根路径
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": config.GetString("app.name"),
			"version": config.GetString("app.version"),
		})
	})

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Swagger 文档
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Auth 路由（OAuth2.1/OIDC 风格）
	authGroup := r.Group("/auth")
	{
		authGroup.GET("/authorize", app.AuthHandler.Authorize) // 创建认证会话并重定向到登录页面
		authGroup.POST("/login", app.AuthHandler.Login)        // IDP 登录
		authGroup.POST("/token", app.AuthHandler.Token)        // 获取/刷新 Token
		authGroup.POST("/revoke", app.AuthHandler.Revoke)      // 撤销 Token
		authGroup.POST("/logout", middleware.RequireAuth(), app.AuthHandler.Logout)
		authGroup.GET("/userinfo", middleware.RequireAuth(), app.AuthHandler.UserInfo)
		authGroup.PUT("/userinfo", middleware.RequireAuth(), app.AuthHandler.UpdateUserInfo)
	}

	// IDPs 路由（获取认证源配置）
	r.GET("/idps", app.AuthHandler.IDPs) // 获取认证源配置

	// API 路由
	api := r.Group("/api")
	{
		// 菜谱路由
		recipes := api.Group("/recipes")
		{
			recipes.POST("", app.RecipeHandler.CreateRecipe)
			recipes.GET("", app.RecipeHandler.GetRecipes)
			recipes.GET("/categories/list", app.RecipeHandler.GetCategories)
			recipes.POST("/batch", app.RecipeHandler.CreateRecipesBatch)
			recipes.GET("/:recipe_id", app.RecipeHandler.GetRecipe)
			recipes.PUT("/:recipe_id", app.RecipeHandler.UpdateRecipe)
			recipes.DELETE("/:recipe_id", app.RecipeHandler.DeleteRecipe)
		}

		// 用户相关路由（统一使用 /user 前缀）
		user := api.Group("/user")
		{
			// 收藏路由
			favorites := user.Group("/favorites")
			favorites.Use(middleware.RequireAuth())
			{
				favorites.GET("", app.FavoriteHandler.GetFavorites)
				favorites.POST("", app.FavoriteHandler.AddFavorite)
				favorites.POST("/batch-check", app.FavoriteHandler.BatchCheckFavorites)
				favorites.GET("/:recipe_id/check", app.FavoriteHandler.CheckFavorite)
				favorites.DELETE("/:recipe_id", app.FavoriteHandler.RemoveFavorite)
			}

			// 浏览历史路由
			history := user.Group("/history")
			history.Use(middleware.RequireAuth())
			{
				history.GET("", app.HistoryHandler.GetViewHistory)
				history.POST("", app.HistoryHandler.AddViewHistory)
				history.DELETE("", app.HistoryHandler.ClearViewHistory)
				history.DELETE("/:recipe_id", app.HistoryHandler.RemoveViewHistory)
			}

			// 用户偏好路由
			preference := user.Group("/preference")
			{
				preference.GET("", middleware.RequireAuth(), app.PreferenceHandler.GetUserPreferences)    // 获取用户偏好（需登录）
				preference.PUT("", middleware.RequireAuth(), app.PreferenceHandler.UpdateUserPreferences) // 更新用户偏好（需登录）
			}
		}

		// 首页路由
		home := api.Group("/home")
		{
			home.GET("/banners", app.HomeHandler.GetBanners)
			home.GET("/recommend", app.HomeHandler.GetRecommendRecipes)
			home.GET("/hot", app.HomeHandler.GetHotRecipes)
		}

		// 偏好选项路由（无需登录，获取所有可选选项）
		api.GET("/preferences", app.PreferenceHandler.GetOptions)

		// 标签路由（RESTful 风格，统一管理所有标签和选项）
		tags := api.Group("/tags")
		{
			// GET /api/tags - 获取标签列表（支持查询参数）
			// GET /api/tags?type=cuisine - 获取特定类型的标签
			// GET /api/tags?type=taboo - 获取特定类型的选项
			// GET /api/tags?type=flavor&recipe_id=xxx - 获取特定菜谱的标签
			tags.GET("", app.TagHandler.ListTags)

			// GET /api/tags/{type} - 获取特定类型的标签/选项
			// 支持所有类型：cuisine/flavor/scene/taboo/allergy
			tags.GET("/:type", app.TagHandler.GetTagsByType)

			// POST /api/tags - 创建标签/选项（后台管理）
			// recipe_id 为空时创建选项，不为空时创建菜谱标签
			tags.POST("", middleware.RequireAuth(), app.TagHandler.CreateTag)

			// PUT /api/tags/{type}/{value} - 更新标签/选项（后台管理）
			// recipe_id 查询参数为空时更新选项，不为空时更新菜谱标签
			tags.PUT("/:type/:value", middleware.RequireAuth(), app.TagHandler.UpdateTag)

			// DELETE /api/tags/{type}/{value} - 删除标签/选项（后台管理）
			// recipe_id 查询参数为空时删除选项，不为空时删除菜谱标签
			tags.DELETE("/:type/:value", middleware.RequireAuth(), app.TagHandler.DeleteTag)

			// 向后兼容的旧接口
			tags.GET("/cuisines", app.TagHandler.GetCuisines)
			tags.GET("/flavors", app.TagHandler.GetFlavors)
			tags.GET("/scenes", app.TagHandler.GetScenes)
		}

		// 推荐路由
		recommend := api.Group("/recommend")
		{
			// LLM 推荐菜谱（支持可选认证）
			recommend.Use(middleware.AuthMiddleware())
			recommend.POST("", app.RecommendHandler.GetRecommendations)

			// 获取推荐上下文信息（需要登录）
			recommend.Use(middleware.RequireAuth())
			recommend.POST("/context", app.RecommendHandler.GetContext)
		}

		// 上传路由
		upload := api.Group("/upload")
		upload.Use(middleware.RequireAuth())
		{
			upload.POST("/image", app.UploadHandler.UploadImage)
		}
	}

	// Hermes 身份与访问管理路由
	hermes := r.Group("/hermes")
	hermes.Use(middleware.RequireAuth())
	{
		// 域管理
		domains := hermes.Group("/domains")
		{
			domains.GET("", app.HermesHandler.ListDomains)
			domains.GET("/:domain_id", app.HermesHandler.GetDomain)
		}

		// 服务管理
		services := hermes.Group("/services")
		{
			services.GET("", app.HermesHandler.ListServices)
			services.POST("", app.HermesHandler.CreateService)
			services.GET("/:service_id", app.HermesHandler.GetService)
			services.PUT("/:service_id", app.HermesHandler.UpdateService)
		}

		// 应用管理
		applications := hermes.Group("/applications")
		{
			applications.GET("", app.HermesHandler.ListApplications)
			applications.POST("", app.HermesHandler.CreateApplication)
			applications.GET("/:app_id", app.HermesHandler.GetApplication)
			applications.PUT("/:app_id", app.HermesHandler.UpdateApplication)
			applications.GET("/:app_id/applicable", app.HermesHandler.GetApplicationServiceRelations)
			applications.POST("/:app_id/services/:service_id/applicable", app.HermesHandler.SetApplicationServiceRelations)

			// 应用下的服务关系管理（RESTful 风格）
			appServices := applications.Group("/:app_id/services/:service_id")
			{
				appServices.GET("/relationships", app.HermesHandler.ListAppServiceRelationships)
				appServices.POST("/relationships", app.HermesHandler.CreateAppServiceRelationship)
				appServices.PUT("/relationships/:relationship_id", app.HermesHandler.UpdateAppServiceRelationship)
				appServices.DELETE("/relationships/:relationship_id", app.HermesHandler.DeleteAppServiceRelationship)
			}
		}

		// 关系管理（通用查询接口，保留向后兼容）
		relationships := hermes.Group("/relationships")
		{
			relationships.GET("", app.HermesHandler.ListRelationships)
		}

		// 组管理
		groups := hermes.Group("/groups")
		{
			groups.GET("", app.HermesHandler.ListGroups)
			groups.POST("", app.HermesHandler.CreateGroup)
			groups.GET("/:group_id", app.HermesHandler.GetGroup)
			groups.PUT("/:group_id", app.HermesHandler.UpdateGroup)
			groups.GET("/:group_id/members", app.HermesHandler.GetGroupMembers)
			groups.POST("/:group_id/members", app.HermesHandler.SetGroupMembers)
		}
	}

	// 启动服务器
	addr := fmt.Sprintf("%s:%d", config.GetString("server.host"), config.GetInt("server.port"))
	logger.Infof("服务启动: http://%s", addr)
	logger.Infof("API 文档: http://%s/swagger/index.html", addr)

	if err := r.Run(addr); err != nil {
		logger.Fatalf("服务启动失败: %v", err)
	}
}
