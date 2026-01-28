//go:build wireinject
// +build wireinject

package main

import (
	"github.com/heliannuuthus/helios/internal/auth"
	"github.com/heliannuuthus/helios/internal/database"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/internal/hermes/upload"
	"github.com/heliannuuthus/helios/internal/zwei/favorite"
	"github.com/heliannuuthus/helios/internal/zwei/history"
	"github.com/heliannuuthus/helios/internal/zwei/home"
	"github.com/heliannuuthus/helios/internal/zwei/preference"
	"github.com/heliannuuthus/helios/internal/zwei/recipe"
	"github.com/heliannuuthus/helios/internal/zwei/recommend"
	"github.com/heliannuuthus/helios/internal/zwei/tag"

	"github.com/google/wire"
	"gorm.io/gorm"
)

// 业务模块 Handler（使用 Zwei 数据库）
func provideRecipeHandler() *recipe.Handler {
	return recipe.NewHandler(database.GetZwei())
}

func provideFavoriteHandler() *favorite.Handler {
	return favorite.NewHandler(database.GetZwei())
}

func provideHistoryHandler() *history.Handler {
	return history.NewHandler(database.GetZwei())
}

func providePreferenceHandler() *preference.Handler {
	return preference.NewHandler(database.GetZwei())
}

func provideTagHandler() *tag.Handler {
	return tag.NewHandler(database.GetZwei())
}

func provideRecommendHandler() *recommend.Handler {
	return recommend.NewHandler(database.GetZwei())
}

func provideHomeHandler() *home.Handler {
	return home.NewHandler(database.GetZwei())
}

// Hermes Service（供 auth 模块复用）
func provideHermesService() *hermes.Service {
	return hermes.NewService()
}

// 认证模块 Handler（使用 Auth 数据库，依赖 hermes.Service）
func provideAuthHandler(hermesService *hermes.Service) (*auth.Handler, error) {
	authService, err := auth.NewService(database.GetAuth(), hermesService)
	if err != nil {
		return nil, err
	}
	return auth.NewHandler(authService), nil
}

func provideUploadHandler() *upload.Handler {
	return upload.NewHandler(database.GetAuth())
}

func provideHermesHandler(hermesService *hermes.Service) *hermes.Handler {
	return hermes.NewHandler(hermesService)
}

// provideDB 提供默认数据库连接（用于 App.DB 字段，保持兼容性）
func provideDB() *gorm.DB {
	return database.Get()
}

// ProviderSet 提供者集合
var ProviderSet = wire.NewSet(
	provideDB, // 默认数据库连接
	// 业务模块（使用 Zwei 数据库）
	recipe.NewService,
	favorite.NewService,
	history.NewService,
	preference.NewService,
	tag.NewService,
	recommend.NewService,
	provideRecipeHandler,
	provideFavoriteHandler,
	provideHistoryHandler,
	providePreferenceHandler,
	provideTagHandler,
	provideRecommendHandler,
	provideHomeHandler,
	// Hermes 模块（使用 Auth 数据库，提供给 auth 复用）
	provideHermesService,
	provideHermesHandler,
	// 认证模块（使用 Auth 数据库，依赖 hermes.Service）
	provideAuthHandler,
	provideUploadHandler,
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
	HermesHandler *hermes.Handler
}

// InitializeApp 初始化应用（由 wire 生成）
func InitializeApp() (*App, error) {
	wire.Build(
		ProviderSet,
		wire.Struct(new(App), "*"),
	)
	return nil, nil
}
