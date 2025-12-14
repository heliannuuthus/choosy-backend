package handlers

import (
	"math/rand"
	"net/http"
	"strconv"
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

// GetBanners 获取首页 Banner
// @Summary 获取首页 Banner
// @Tags home
// @Produce json
// @Success 200 {array} BannerItem
// @Router /api/home/banners [get]
func (h *HomeHandler) GetBanners(c *gin.Context) {
	banners := h.loadBannersFromConfig()
	c.JSON(http.StatusOK, banners)
}

// GetRecommendRecipes 获取推荐菜谱
// @Summary 获取推荐菜谱（随机）
// @Tags home
// @Produce json
// @Param limit query int false "数量限制" default(4)
// @Success 200 {array} RecipeListItem
// @Router /api/home/recommend [get]
func (h *HomeHandler) GetRecommendRecipes(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "4"))
	if limit < 1 {
		limit = 1
	} else if limit > 20 {
		limit = 20
	}

	recipes := h.getRandomRecipes(limit)
	c.JSON(http.StatusOK, recipes)
}

// GetHotRecipes 获取热门菜谱
// @Summary 获取热门菜谱（按收藏数排序）
// @Tags home
// @Produce json
// @Param limit query int false "数量限制" default(6)
// @Success 200 {array} RecipeListItem
// @Router /api/home/hot [get]
func (h *HomeHandler) GetHotRecipes(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "6"))
	if limit < 1 {
		limit = 1
	} else if limit > 20 {
		limit = 20
	}

	recipes := h.getHotRecipes(limit)
	c.JSON(http.StatusOK, recipes)
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
			ID:               r.RecipeID,
			Name:             r.Name,
			Description:      r.Description,
			Category:         r.Category,
			Difficulty:       r.Difficulty,
			Tags:             GroupTags(r.Tags),
			ImagePath:        r.GetImagePath(),
			TotalTimeMinutes: r.TotalTimeMinutes,
		}
	}

	return items
}

// getRandomRecipes 获取随机菜谱
func (h *HomeHandler) getRandomRecipes(count int) []RecipeListItem {
	recipes, _ := h.recipeService.GetRecipes("", "", 100, 0)
	if len(recipes) == 0 {
		return []RecipeListItem{}
	}

	// 转换为 RecipeListItem
	var items []RecipeListItem
	for _, r := range recipes {
		items = append(items, RecipeListItem{
			ID:               r.RecipeID,
			Name:             r.Name,
			Description:      r.Description,
			Category:         r.Category,
			Difficulty:       r.Difficulty,
			Tags:             GroupTags(r.Tags),
			ImagePath:        r.GetImagePath(),
			TotalTimeMinutes: r.TotalTimeMinutes,
		})
	}

	// 随机打乱
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(items), func(i, j int) {
		items[i], items[j] = items[j], items[i]
	})

	// 取前 count 个
	if len(items) > count {
		items = items[:count]
	}

	return items
}
