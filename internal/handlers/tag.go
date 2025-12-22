package handlers

import (
	"net/http"

	"choosy-backend/internal/models"
	"choosy-backend/internal/tag"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// TagHandler 标签处理器
type TagHandler struct {
	service *tag.Service
}

// NewTagHandler 创建标签处理器
func NewTagHandler(db *gorm.DB) *TagHandler {
	return &TagHandler{
		service: tag.NewService(db),
	}
}

type TagValueResponse struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// GetCuisines 获取所有菜系
// @Summary 获取所有菜系
// @Tags tags
// @Produce json
// @Success 200 {array} TagValueResponse
// @Router /api/tags/cuisines [get]
func (h *TagHandler) GetCuisines(c *gin.Context) {
	results, err := h.service.GetDistinctTagValues(models.TagTypeCuisine)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	response := make([]TagValueResponse, len(results))
	for i, r := range results {
		response[i] = TagValueResponse{Value: r.Value, Label: r.Label}
	}
	c.JSON(http.StatusOK, response)
}

// GetFlavors 获取所有口味
// @Summary 获取所有口味
// @Tags tags
// @Produce json
// @Success 200 {array} TagValueResponse
// @Router /api/tags/flavors [get]
func (h *TagHandler) GetFlavors(c *gin.Context) {
	results, err := h.service.GetDistinctTagValues(models.TagTypeFlavor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	response := make([]TagValueResponse, len(results))
	for i, r := range results {
		response[i] = TagValueResponse{Value: r.Value, Label: r.Label}
	}
	c.JSON(http.StatusOK, response)
}

// GetScenes 获取所有场景
// @Summary 获取所有场景
// @Tags tags
// @Produce json
// @Success 200 {array} TagValueResponse
// @Router /api/tags/scenes [get]
func (h *TagHandler) GetScenes(c *gin.Context) {
	results, err := h.service.GetDistinctTagValues(models.TagTypeScene)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	response := make([]TagValueResponse, len(results))
	for i, r := range results {
		response[i] = TagValueResponse{Value: r.Value, Label: r.Label}
	}
	c.JSON(http.StatusOK, response)
}
