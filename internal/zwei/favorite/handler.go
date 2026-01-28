package favorite

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/auth"
)

// Handler 收藏处理器
type Handler struct {
	service *Service
}

// NewHandler 创建收藏处理器
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		service: NewService(db),
	}
}

type FavoriteRequest struct {
	RecipeID string `json:"recipe_id" binding:"required"`
}

type FavoriteResponse struct {
	RecipeID  string `json:"recipe_id"`
	CreatedAt string `json:"created_at"`
}

type FavoriteListItem struct {
	RecipeID  string          `json:"recipe_id"`
	CreatedAt string          `json:"created_at"`
	Recipe    *RecipeListItem `json:"recipe,omitempty"`
}

type FavoriteListResponse struct {
	Items []FavoriteListItem `json:"items"`
	Total int64              `json:"total"`
}

type CheckFavoriteResponse struct {
	IsFavorite bool `json:"is_favorite"`
}

type BatchCheckRequest struct {
	RecipeIDs []string `json:"recipe_ids" binding:"required"`
}

type BatchCheckResponse struct {
	FavoritedIDs []string `json:"favorited_ids"`
}

// AddFavorite 添加收藏
// @Summary 添加收藏
// @Tags favorites
// @Accept json
// @Produce json
// @Param favorite body FavoriteRequest true "收藏信息"
// @Success 201 {object} FavoriteResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/user/favorites [post]
func (h *Handler) AddFavorite(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录"})
		return
	}

	identity := user.(*auth.Claims)
	openID := identity.GetOpenID()

	var req FavoriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	fav, err := h.service.AddFavorite(openID, req.RecipeID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, FavoriteResponse{
		RecipeID:  fav.RecipeID,
		CreatedAt: fav.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// RemoveFavorite 取消收藏
// @Summary 取消收藏
// @Tags favorites
// @Param recipe_id path string true "菜谱ID"
// @Success 204
// @Failure 401 {object} map[string]string
// @Router /api/user/favorites/{recipe_id} [delete]
func (h *Handler) RemoveFavorite(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录"})
		return
	}

	identity := user.(*auth.Claims)
	openID := identity.GetOpenID()
	recipeID := c.Param("recipe_id")

	if err := h.service.RemoveFavorite(openID, recipeID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// CheckFavorite 检查是否已收藏
// @Summary 检查是否已收藏
// @Tags favorites
// @Produce json
// @Param recipe_id path string true "菜谱ID"
// @Success 200 {object} CheckFavoriteResponse
// @Failure 401 {object} map[string]string
// @Router /api/user/favorites/{recipe_id}/check [get]
func (h *Handler) CheckFavorite(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录"})
		return
	}

	identity := user.(*auth.Claims)
	openID := identity.GetOpenID()
	recipeID := c.Param("recipe_id")

	isFavorite, err := h.service.IsFavorite(openID, recipeID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, CheckFavoriteResponse{
		IsFavorite: isFavorite,
	})
}

// GetFavorites 获取收藏列表
// @Summary 获取收藏列表
// @Tags favorites
// @Produce json
// @Param category query string false "分类筛选"
// @Param search query string false "搜索关键词"
// @Param limit query int false "限制数量" default(20)
// @Param offset query int false "偏移量" default(0)
// @Success 200 {object} FavoriteListResponse
// @Failure 401 {object} map[string]string
// @Router /api/user/favorites [get]
func (h *Handler) GetFavorites(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录"})
		return
	}

	identity := user.(*auth.Claims)
	openID := identity.GetOpenID()

	category := c.Query("category")
	search := c.Query("search")

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit < 1 {
		limit = 1
	} else if limit > 100 {
		limit = 100
	}

	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if offset < 0 {
		offset = 0
	}

	favorites, total, err := h.service.GetFavorites(openID, category, search, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	items := make([]FavoriteListItem, len(favorites))
	for i, f := range favorites {
		item := FavoriteListItem{
			RecipeID:  f.RecipeID,
			CreatedAt: f.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}

		if f.Recipe != nil {
			item.Recipe = &RecipeListItem{
				ID:               f.Recipe.RecipeID,
				Name:             f.Recipe.Name,
				Description:      f.Recipe.Description,
				Category:         f.Recipe.Category,
				Difficulty:       f.Recipe.Difficulty,
				Tags:             GroupTags(f.Recipe.Tags),
				ImagePath:        f.Recipe.GetImagePath(),
				TotalTimeMinutes: f.Recipe.TotalTimeMinutes,
			}
		}

		items[i] = item
	}

	c.JSON(http.StatusOK, FavoriteListResponse{
		Items: items,
		Total: total,
	})
}

// BatchCheckFavorites 批量检查收藏状态
// @Summary 批量检查收藏状态
// @Tags favorites
// @Accept json
// @Produce json
// @Param request body BatchCheckRequest true "菜谱ID列表"
// @Success 200 {object} BatchCheckResponse
// @Failure 401 {object} map[string]string
// @Router /api/user/favorites/batch-check [post]
func (h *Handler) BatchCheckFavorites(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录"})
		return
	}

	identity := user.(*auth.Claims)
	openID := identity.GetOpenID()

	var req BatchCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	favoritedIDs, err := h.service.GetFavoriteRecipeIDs(openID, req.RecipeIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, BatchCheckResponse{
		FavoritedIDs: favoritedIDs,
	})
}
