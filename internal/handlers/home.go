package handlers

import (
	"math/rand"
	"net/http"
	"time"

	"choosy-backend/internal/config"
	"choosy-backend/internal/services"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// HomeHandler 首页处理器
type HomeHandler struct {
	recipeService *services.RecipeService
}

// NewHomeHandler 创建首页处理器
func NewHomeHandler(db *gorm.DB) *HomeHandler {
	return &HomeHandler{
		recipeService: services.NewRecipeService(db),
	}
}

// BannerItem 海报项
type BannerItem struct {
	ID       string `json:"id"`
	ImageURL string `json:"image_url"`
	Title    string `json:"title,omitempty"`
	Link     string `json:"link,omitempty"`
	LinkType string `json:"link_type,omitempty"` // recipe, url, none
}

// HomeConfigResponse 首页配置响应
type HomeConfigResponse struct {
	Banners          []BannerItem     `json:"banners"`
	RecommendRecipes []RecipeListItem `json:"recommend_recipes"`
	HotRecipes       []RecipeListItem `json:"hot_recipes"`
}

// GetHomeConfig 获取首页配置
// @Summary 获取首页配置
// @Tags home
// @Produce json
// @Success 200 {object} HomeConfigResponse
// @Router /api/home/config [get]
func (h *HomeHandler) GetHomeConfig(c *gin.Context) {
	// 从配置文件读取 banners
	banners := h.loadBannersFromConfig()

	// 获取热门菜谱（按收藏数排序，取前 6 个）
	hotRecipes := h.getHotRecipes(6)

	// 获取推荐菜谱（随机 4 个，排除热门）
	excludeIDs := make([]string, len(hotRecipes))
	for i, r := range hotRecipes {
		excludeIDs[i] = r.ID
	}
	recommendRecipes := h.getRandomRecipesExclude(4, excludeIDs)

	c.JSON(http.StatusOK, HomeConfigResponse{
		Banners:          banners,
		RecommendRecipes: recommendRecipes,
		HotRecipes:       hotRecipes,
	})
}

// loadBannersFromConfig 从配置文件加载 banners
func (h *HomeHandler) loadBannersFromConfig() []BannerItem {
	var banners []BannerItem

	// 读取配置中的 banners 数组
	bannersConfig := config.Get("home.banners")
	if bannersConfig == nil {
		return banners
	}

	// 尝试转换为 []interface{}
	bannersList, ok := bannersConfig.([]interface{})
	if !ok {
		return banners
	}

	for i, item := range bannersList {
		bannerMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		banner := BannerItem{
			ID: getString(bannerMap, "id", generateBannerID(i)),
		}

		if imageURL := getString(bannerMap, "image_url", ""); imageURL != "" {
			banner.ImageURL = imageURL
		}
		if title := getString(bannerMap, "title", ""); title != "" {
			banner.Title = title
		}
		if link := getString(bannerMap, "link", ""); link != "" {
			banner.Link = link
		}
		if linkType := getString(bannerMap, "link_type", "none"); linkType != "" {
			banner.LinkType = linkType
		}

		banners = append(banners, banner)
	}

	return banners
}

// getString 从 map 中获取字符串
func getString(m map[string]interface{}, key, defaultVal string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultVal
}

// generateBannerID 生成 banner ID
func generateBannerID(index int) string {
	return "banner_" + string(rune('a'+index))
}

// getHotRecipes 获取热门菜谱（按收藏数排序）
func (h *HomeHandler) getHotRecipes(count int) []RecipeListItem {
	recipes, _ := h.recipeService.GetHotRecipes(count, nil)
	if len(recipes) == 0 {
		return []RecipeListItem{}
	}

	items := make([]RecipeListItem, len(recipes))
	for i, r := range recipes {
		items[i] = RecipeListItem{
			ID:               r.ID,
			Name:             r.Name,
			Description:      r.Description,
			Category:         r.Category,
			Difficulty:       r.Difficulty,
			Tags:             r.Tags,
			ImagePath:        r.ImagePath,
			TotalTimeMinutes: r.TotalTimeMinutes,
		}
	}

	return items
}

// getRandomRecipesExclude 获取随机菜谱（排除指定 ID）
func (h *HomeHandler) getRandomRecipesExclude(count int, excludeIDs []string) []RecipeListItem {
	recipes, _ := h.recipeService.GetRecipes("", "", 100, 0)
	if len(recipes) == 0 {
		return []RecipeListItem{}
	}

	// 构建排除 ID 集合
	excludeMap := make(map[string]bool)
	for _, id := range excludeIDs {
		excludeMap[id] = true
	}

	// 过滤掉已排除的
	var filtered []RecipeListItem
	for _, r := range recipes {
		if !excludeMap[r.ID] {
			filtered = append(filtered, RecipeListItem{
				ID:               r.ID,
				Name:             r.Name,
				Description:      r.Description,
				Category:         r.Category,
				Difficulty:       r.Difficulty,
				Tags:             r.Tags,
				ImagePath:        r.ImagePath,
				TotalTimeMinutes: r.TotalTimeMinutes,
			})
		}
	}

	// 随机打乱
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(filtered), func(i, j int) {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	})

	// 取前 count 个
	if len(filtered) > count {
		filtered = filtered[:count]
	}

	return filtered
}
