//go:build wireinject
// +build wireinject

package main

import (
	"zwei-backend/internal/auth"
	"zwei-backend/internal/database"
	"zwei-backend/internal/favorite"
	"zwei-backend/internal/history"
	"zwei-backend/internal/home"
	"zwei-backend/internal/preference"
	"zwei-backend/internal/recipe"
	"zwei-backend/internal/recommend"
	"zwei-backend/internal/tag"
	"zwei-backend/internal/upload"

	"github.com/google/wire"
	"gorm.io/gorm"
)

// ProviderSet 提供者集合
var ProviderSet = wire.NewSet(
	database.Get,
	recipe.NewService,
	auth.NewService,
	favorite.NewService,
	history.NewService,
	preference.NewService,
	tag.NewService,
	recommend.NewService,
	recipe.NewHandler,
	auth.NewHandler,
	favorite.NewHandler,
	history.NewHandler,
	home.NewHandler,
	tag.NewHandler,
	recommend.NewHandler,
	upload.NewHandler,
	preference.NewHandler,
)

// App 应用依赖容器
type App struct {
	DB                *gorm.DB
	RecipeHandler     *recipe.Handler
	AuthHandler       *auth.Handler
	FavoriteHandler   *favorite.Handler
	HistoryHandler    *history.Handler
	HomeHandler       *home.Handler
	TagHandler        *tag.Handler
	RecommendHandler  *recommend.Handler
	UploadHandler     *upload.Handler
	PreferenceHandler *preference.Handler
}

// InitializeApp 初始化应用（由 wire 生成）
func InitializeApp() (*App, error) {
	wire.Build(
		ProviderSet,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
