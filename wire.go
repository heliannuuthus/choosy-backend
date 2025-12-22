//go:build wireinject
// +build wireinject

package main

import (
	"choosy-backend/internal/auth"
	"choosy-backend/internal/database"
	"choosy-backend/internal/favorite"
	"choosy-backend/internal/handlers"
	"choosy-backend/internal/recipe"
	"choosy-backend/internal/recommend"
	"choosy-backend/internal/tag"

	"github.com/google/wire"
	"gorm.io/gorm"
)

// ProviderSet 提供者集合
var ProviderSet = wire.NewSet(
	database.Get,
	recipe.NewService,
	auth.NewService,
	favorite.NewService,
	tag.NewService,
	recommend.NewService,
	handlers.NewRecipeHandler,
	handlers.NewAuthHandler,
	handlers.NewFavoriteHandler,
	handlers.NewHomeHandler,
	handlers.NewTagHandler,
	handlers.NewRecommendHandler,
)

// App 应用依赖容器
type App struct {
	DB               *gorm.DB
	RecipeHandler    *handlers.RecipeHandler
	AuthHandler      *handlers.AuthHandler
	FavoriteHandler  *handlers.FavoriteHandler
	HomeHandler      *handlers.HomeHandler
	TagHandler       *handlers.TagHandler
	RecommendHandler *handlers.RecommendHandler
}

// InitializeApp 初始化应用（由 wire 生成）
func InitializeApp() (*App, error) {
	wire.Build(
		ProviderSet,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
