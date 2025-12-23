package handlers

import (
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"choosy-backend/internal/config"
	"choosy-backend/internal/recipe"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// HomeHandler 首页处理器
type HomeHandler struct {
	recipeService *recipe.Service
}

// NewHomeHandler 创建首页处理器
func NewHomeHandler(db *gorm.DB) *HomeHandler {
	return &HomeHandler{
		recipeService: recipe.NewService(db),
	}
}

type BannerItem struct {
	ID       string `json:"id"`
	ImageURL string `json:"image_url"`
	Title    string `json:"title,omitempty"`
	Link     string `json:"link,omitempty"`
	LinkType string `json:"link_type,omitempty"`
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

func (h *HomeHandler) loadBannersFromConfig() []BannerItem {
	var banners []BannerItem

	bannersConfig := config.Get("home.banners")
	if bannersConfig == nil {
		return banners
	}

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

func getString(m map[string]interface{}, key, defaultVal string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultVal
}

func generateBannerID(index int) string {
	return "banner_" + string(rune('a'+index))
}

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

func (h *HomeHandler) getRandomRecipes(count int) []RecipeListItem {
	recipes, _ := h.recipeService.GetRecipes("", "", 100, 0)
	if len(recipes) == 0 {
		return []RecipeListItem{}
	}

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

	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(items), func(i, j int) {
		items[i], items[j] = items[j], items[i]
	})

	if len(items) > count {
		items = items[:count]
	}

	return items
}
