package main

import (
	"fmt"

	"choosy-backend/internal/config"
	"choosy-backend/internal/handlers"
	"choosy-backend/internal/logger"
	"choosy-backend/internal/middleware"

	_ "choosy-backend/docs" // swagger docs

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Choosy API
// @version 1.0
// @description 菜谱管理系统后端 API

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
	logger.Init()
	defer logger.Sync()

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

	// API 路由
	api := r.Group("/api")
	{
		// 认证路由（OAuth2.1 风格）
		auth := api.Group("/auth")
		{
			auth.POST("/token", app.AuthHandler.Token)   // 获取/刷新 token
			auth.POST("/revoke", app.AuthHandler.Revoke) // 撤销 token
			auth.POST("/revoke-all", middleware.RequireAuth(), app.AuthHandler.LogoutAll)
			auth.GET("/profile", middleware.RequireAuth(), app.AuthHandler.Profile)
			auth.PUT("/profile", middleware.RequireAuth(), app.AuthHandler.UpdateProfile)
		}

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

		// 收藏路由
		favorites := api.Group("/favorites")
		favorites.Use(middleware.RequireAuth())
		{
			favorites.GET("", app.FavoriteHandler.GetFavorites)
			favorites.POST("", app.FavoriteHandler.AddFavorite)
			favorites.POST("/batch-check", app.FavoriteHandler.BatchCheckFavorites)
			favorites.GET("/:recipe_id/check", app.FavoriteHandler.CheckFavorite)
			favorites.DELETE("/:recipe_id", app.FavoriteHandler.RemoveFavorite)
		}

		// 浏览历史路由
		history := api.Group("/history")
		history.Use(middleware.RequireAuth())
		{
			history.GET("", app.HistoryHandler.GetViewHistory)
			history.POST("", app.HistoryHandler.AddViewHistory)
			history.DELETE("", app.HistoryHandler.ClearViewHistory)
			history.DELETE("/:recipe_id", app.HistoryHandler.RemoveViewHistory)
		}

		// 首页路由
		home := api.Group("/home")
		{
			home.GET("/banners", app.HomeHandler.GetBanners)
			home.GET("/hot", app.HomeHandler.GetHotRecipes)
		}

		// 标签路由
		tags := api.Group("/tags")
		{
			tags.GET("/cuisines", app.TagHandler.GetCuisines)
			tags.GET("/flavors", app.TagHandler.GetFlavors)
			tags.GET("/scenes", app.TagHandler.GetScenes)
		}

		// 推荐路由
		contextHandler := handlers.NewContextHandler()
		recommend := api.Group("/recommend")
		{
			// LLM 推荐菜谱（支持可选认证）
			recommend.Use(middleware.AuthMiddleware())
			recommend.POST("", app.RecommendHandler.GetRecommendations)

			// 获取上下文信息（需要登录）
			recommend.Use(middleware.RequireAuth())
			recommend.POST("/context", contextHandler.GetContext)
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
