package home

import (
	"math/rand"
	"net/http"
	"strconv"

	"zwei-backend/internal/config"
	"zwei-backend/internal/recipe"
	"zwei-backend/internal/types"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Handler 首页处理器
type Handler struct {
	recipeService *recipe.Service
}

// NewHandler 创建首页处理器
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
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
func (h *Handler) GetBanners(c *gin.Context) {
	banners := h.loadBannersFromConfig()
	c.JSON(http.StatusOK, banners)
}

// GetRecommendRecipes 获取推荐菜谱
// @Summary 获取推荐菜谱（随机）
// @Tags home
// @Produce json
// @Param limit query int false "数量限制" default(4)
// @Success 200 {array} types.RecipeListItem
// @Router /api/home/recommend [get]
func (h *Handler) GetRecommendRecipes(c *gin.Context) {
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
// @Success 200 {array} types.RecipeListItem
// @Router /api/home/hot [get]
func (h *Handler) GetHotRecipes(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "6"))
	if limit < 1 {
		limit = 1
	} else if limit > 20 {
		limit = 20
	}

	recipes := h.getHotRecipes(limit)
	c.JSON(http.StatusOK, recipes)
}

func (h *Handler) loadBannersFromConfig() []BannerItem {
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

		if imageURL := getString(bannerMap, "image-url", ""); imageURL != "" {
			banner.ImageURL = imageURL
		}
		if title := getString(bannerMap, "title", ""); title != "" {
			banner.Title = title
		}
		if link := getString(bannerMap, "link", ""); link != "" {
			banner.Link = link
		}
		if linkType := getString(bannerMap, "link-type", "none"); linkType != "" {
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

func (h *Handler) getHotRecipes(count int) []types.RecipeListItem {
	recipes, _ := h.recipeService.GetHotRecipes(count, nil)
	if len(recipes) == 0 {
		return []types.RecipeListItem{}
	}

	items := make([]types.RecipeListItem, len(recipes))
	for i, r := range recipes {
		items[i] = types.RecipeListItem{
			ID:               r.RecipeID,
			Name:             r.Name,
			Description:      r.Description,
			Category:         r.Category,
			Difficulty:       r.Difficulty,
			Tags:             types.GroupTags(r.Tags),
			ImagePath:        r.GetImagePath(),
			TotalTimeMinutes: r.TotalTimeMinutes,
		}
	}

	return items
}

func (h *Handler) getRandomRecipes(count int) []types.RecipeListItem {
	recipes, _ := h.recipeService.GetRecipes("", "", 100, 0)
	if len(recipes) == 0 {
		return []types.RecipeListItem{}
	}

	var items []types.RecipeListItem
	for _, r := range recipes {
		items = append(items, types.RecipeListItem{
			ID:               r.RecipeID,
			Name:             r.Name,
			Description:      r.Description,
			Category:         r.Category,
			Difficulty:       r.Difficulty,
			Tags:             types.GroupTags(r.Tags),
			ImagePath:        r.GetImagePath(),
			TotalTimeMinutes: r.TotalTimeMinutes,
		})
	}

	rand.Shuffle(len(items), func(i, j int) {
		items[i], items[j] = items[j], items[i]
	})

	if len(items) > count {
		items = items[:count]
	}

	return items
}
