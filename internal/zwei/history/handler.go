package history

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/auth"
)

// Handler 浏览历史处理器
type Handler struct {
	service *Service
}

// NewHandler 创建浏览历史处理器
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		service: NewService(db),
	}
}

type HistoryRequest struct {
	RecipeID string `json:"recipe_id" binding:"required"`
}

type HistoryResponse struct {
	RecipeID string `json:"recipe_id"`
	ViewedAt string `json:"viewed_at"`
}

type HistoryListItem struct {
	RecipeID string          `json:"recipe_id"`
	ViewedAt string          `json:"viewed_at"`
	Recipe   *RecipeListItem `json:"recipe,omitempty"`
}

type HistoryListResponse struct {
	Items []HistoryListItem `json:"items"`
	Total int64             `json:"total"`
}

// AddViewHistory 添加浏览记录
// @Summary 添加浏览记录
// @Tags history
// @Accept json
// @Produce json
// @Param history body HistoryRequest true "浏览记录信息"
// @Success 201 {object} HistoryResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/user/history [post]
func (h *Handler) AddViewHistory(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录"})
		return
	}

	identity := user.(*auth.Claims)
	openID := identity.GetOpenID()

	var req HistoryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	hist, err := h.service.AddViewHistory(openID, req.RecipeID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, HistoryResponse{
		RecipeID: hist.RecipeID,
		ViewedAt: hist.ViewedAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// RemoveViewHistory 删除浏览记录
// @Summary 删除浏览记录
// @Tags history
// @Param recipe_id path string true "菜谱ID"
// @Success 204
// @Failure 401 {object} map[string]string
// @Router /api/user/history/{recipe_id} [delete]
func (h *Handler) RemoveViewHistory(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录"})
		return
	}

	identity := user.(*auth.Claims)
	openID := identity.GetOpenID()
	recipeID := c.Param("recipe_id")

	if err := h.service.RemoveViewHistory(openID, recipeID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// ClearViewHistory 清空浏览历史
// @Summary 清空浏览历史
// @Tags history
// @Success 204
// @Failure 401 {object} map[string]string
// @Router /api/user/history [delete]
func (h *Handler) ClearViewHistory(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录"})
		return
	}

	identity := user.(*auth.Claims)
	openID := identity.GetOpenID()

	if err := h.service.ClearViewHistory(openID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetViewHistory 获取浏览历史列表
// @Summary 获取浏览历史列表
// @Tags history
// @Produce json
// @Param category query string false "分类筛选"
// @Param search query string false "搜索关键词"
// @Param limit query int false "限制数量" default(20)
// @Param offset query int false "偏移量" default(0)
// @Success 200 {object} HistoryListResponse
// @Failure 401 {object} map[string]string
// @Router /api/user/history [get]
func (h *Handler) GetViewHistory(c *gin.Context) {
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

	historyList, total, err := h.service.GetViewHistory(openID, category, search, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	items := make([]HistoryListItem, len(historyList))
	for i, h := range historyList {
		item := HistoryListItem{
			RecipeID: h.RecipeID,
			ViewedAt: h.ViewedAt.Format("2006-01-02T15:04:05Z07:00"),
		}

		if h.Recipe != nil {
			item.Recipe = &RecipeListItem{
				ID:               h.Recipe.RecipeID,
				Name:             h.Recipe.Name,
				Description:      h.Recipe.Description,
				Category:         h.Recipe.Category,
				Difficulty:       h.Recipe.Difficulty,
				Tags:             GroupTags(h.Recipe.Tags),
				ImagePath:        h.Recipe.GetImagePath(),
				TotalTimeMinutes: h.Recipe.TotalTimeMinutes,
			}
		}

		items[i] = item
	}

	c.JSON(http.StatusOK, HistoryListResponse{
		Items: items,
		Total: total,
	})
}
