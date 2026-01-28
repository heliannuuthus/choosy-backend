package tag

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/zwei/models"
)

// Handler 标签处理器
type Handler struct {
	service *Service
}

// NewHandler 创建标签处理器
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		service: NewService(db),
	}
}

// TagValueResponse 标签值响应
type TagValueResponse struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// ListTags 获取标签列表（RESTful）
// @Summary 获取标签列表
// @Description 获取标签列表，支持通过查询参数过滤。所有类型（cuisine/flavor/scene/taboo/allergy）都统一使用此接口
// @Tags tags
// @Produce json
// @Param type query string false "标签类型: cuisine/flavor/scene/taboo/allergy"
// @Param recipe_id query string false "菜谱ID（获取特定菜谱的标签，仅用于 cuisine/flavor/scene）"
// @Success 200 {array} TagValueResponse
// @Router /api/tags [get]
func (h *Handler) ListTags(c *gin.Context) {
	tagType := c.Query("type")
	recipeID := c.Query("recipe_id")

	var results []TagValue
	var err error

	if tagType != "" {
		// 验证类型
		validType := models.TagType(tagType)
		if !h.isValidTagType(validType, false) && !h.isValidTagType(validType, true) {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "无效的标签类型"})
			return
		}

		// 选项类型（taboo/allergy）只返回选项，不支持 recipe_id
		if validType == models.TagTypeTaboo || validType == models.TagTypeAllergy {
			if recipeID != "" {
				c.JSON(http.StatusBadRequest, gin.H{"detail": "选项类型不支持 recipe_id 参数"})
				return
			}
			results, err = h.service.GetOptions(validType)
		} else {
			// 标签类型（cuisine/flavor/scene）
			if recipeID != "" {
				// 获取特定菜谱的标签
				results, err = h.service.GetTagsByRecipeAndTypeAsTagValue(recipeID, validType)
			} else {
				// 获取所有该类型的标签（去重）
				results, err = h.service.GetDistinctTagValues(validType)
			}
		}
	} else {
		// 获取所有标签（需要指定 recipe_id）
		if recipeID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "请指定 type 或 recipe_id"})
			return
		}
		results, err = h.service.GetTagsByRecipeAsTagValue(recipeID)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	response := make([]TagValueResponse, len(results))
	for i, r := range results {
		response[i] = TagValueResponse(r)
	}
	c.JSON(http.StatusOK, response)
}

// GetTagsByType 根据类型获取标签
// @Summary 根据类型获取标签
// @Description 支持所有类型：cuisine/flavor/scene/taboo/allergy
// @Tags tags
// @Produce json
// @Param type path string true "标签类型: cuisine/flavor/scene/taboo/allergy"
// @Success 200 {array} TagValueResponse
// @Router /api/tags/{type} [get]
func (h *Handler) GetTagsByType(c *gin.Context) {
	tagTypeStr := c.Param("type")
	tagType := models.TagType(tagTypeStr)

	// 验证类型
	if !h.isValidTagType(tagType, false) && !h.isValidTagType(tagType, true) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "无效的标签类型"})
		return
	}

	var results []TagValue
	var err error

	// 选项类型（taboo/allergy）只返回选项
	if tagType == models.TagTypeTaboo || tagType == models.TagTypeAllergy {
		results, err = h.service.GetOptions(tagType)
	} else {
		// 标签类型（cuisine/flavor/scene）返回所有标签（去重）
		results, err = h.service.GetDistinctTagValues(tagType)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	response := make([]TagValueResponse, len(results))
	for i, r := range results {
		response[i] = TagValueResponse(r)
	}
	c.JSON(http.StatusOK, response)
}

// CreateTagRequest 创建标签请求（后台管理）
type CreateTagRequest struct {
	Type     string `json:"type" binding:"required"`  // 标签类型
	Value    string `json:"value" binding:"required"` // 标签值
	Label    string `json:"label" binding:"required"` // 显示名称
	RecipeID string `json:"recipe_id,omitempty"`      // 菜谱ID（可选，为空时创建选项）
}

// CreateTag 创建标签（后台管理）
// @Summary 创建标签
// @Description 创建标签或选项。如果 recipe_id 为空，创建选项（仅支持 taboo/allergy）；如果 recipe_id 不为空，创建菜谱标签
// @Tags tags
// @Accept json
// @Produce json
// @Param tag body CreateTagRequest true "标签信息"
// @Success 201 {object} TagValueResponse
// @Failure 400 {object} map[string]string
// @Router /api/tags [post]
func (h *Handler) CreateTag(c *gin.Context) {
	var req CreateTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	tagType := models.TagType(req.Type)

	// 验证类型
	if !h.isValidTagType(tagType, false) && !h.isValidTagType(tagType, true) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "无效的标签类型"})
		return
	}

	var err error
	if req.RecipeID == "" {
		// 创建标签定义（选项，仅支持 taboo/allergy）
		if tagType != models.TagTypeTaboo && tagType != models.TagTypeAllergy {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "选项类型仅支持 taboo 和 allergy"})
			return
		}
		err = h.service.AddOption(req.Value, req.Label, tagType)
	} else {
		// 创建菜谱标签（不支持 taboo/allergy）
		if tagType == models.TagTypeTaboo || tagType == models.TagTypeAllergy {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "taboo 和 allergy 类型不能关联菜谱"})
			return
		}
		// AddTag 会自动创建标签定义（如果不存在）并关联到菜谱
		err = h.service.AddTag(req.RecipeID, req.Value, req.Label, tagType)
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, TagValueResponse{
		Value: req.Value,
		Label: req.Label,
	})
}

// UpdateTagRequest 更新标签请求
type UpdateTagRequest struct {
	Label string `json:"label" binding:"required"`
}

// UpdateTag 更新标签（后台管理）
// @Summary 更新标签
// @Description 更新标签或选项的显示名称
// @Tags tags
// @Accept json
// @Produce json
// @Param type path string true "标签类型"
// @Param value path string true "标签值"
// @Param recipe_id query string false "菜谱ID（更新菜谱标签时必填，更新选项时留空）"
// @Param tag body UpdateTagRequest true "更新内容"
// @Success 200 {object} TagValueResponse
// @Failure 400 {object} map[string]string
// @Router /api/tags/{type}/{value} [put]
func (h *Handler) UpdateTag(c *gin.Context) {
	tagTypeStr := c.Param("type")
	value := c.Param("value")
	recipeID := c.Query("recipe_id")
	tagType := models.TagType(tagTypeStr)

	// 验证类型
	if !h.isValidTagType(tagType, false) && !h.isValidTagType(tagType, true) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "无效的标签类型"})
		return
	}

	var req UpdateTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	var err error
	if recipeID == "" {
		// 更新标签定义（选项或标签定义）
		err = h.service.UpdateTag(value, req.Label, tagType)
	} else {
		// 更新菜谱标签：实际上是更新标签定义（因为标签定义是共享的）
		// 注意：这会影响到所有使用该标签的菜谱
		err = h.service.UpdateTag(value, req.Label, tagType)
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, TagValueResponse{
		Value: value,
		Label: req.Label,
	})
}

// DeleteTag 删除标签（后台管理）
// @Summary 删除标签
// @Description 删除标签或选项
// @Tags tags
// @Param type path string true "标签类型"
// @Param value path string true "标签值"
// @Param recipe_id query string false "菜谱ID（删除菜谱标签时必填，删除选项时留空）"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]string
// @Router /api/tags/{type}/{value} [delete]
func (h *Handler) DeleteTag(c *gin.Context) {
	tagTypeStr := c.Param("type")
	value := c.Param("value")
	recipeID := c.Query("recipe_id")
	tagType := models.TagType(tagTypeStr)

	// 验证类型
	if !h.isValidTagType(tagType, false) && !h.isValidTagType(tagType, true) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "无效的标签类型"})
		return
	}

	var err error
	if recipeID == "" {
		// 删除标签定义（选项）
		if tagType != models.TagTypeTaboo && tagType != models.TagTypeAllergy {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "选项类型仅支持 taboo 和 allergy"})
			return
		}
		err = h.service.DeleteOption(value, tagType)
	} else {
		// 删除菜谱的标签关联（不删除标签定义）
		err = h.service.RemoveTagFromRecipe(recipeID, value, tagType)
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// isValidTagType 验证标签类型是否有效
func (h *Handler) isValidTagType(tagType models.TagType, isOption bool) bool {
	allTypes := []models.TagType{
		models.TagTypeCuisine,
		models.TagTypeFlavor,
		models.TagTypeScene,
		models.TagTypeTaboo,
		models.TagTypeAllergy,
	}

	for _, t := range allTypes {
		if tagType == t {
			if isOption {
				// 选项类型
				return tagType == models.TagTypeTaboo || tagType == models.TagTypeAllergy
			}
			// 所有类型都有效
			return true
		}
	}
	return false
}

// ==================== 向后兼容的旧接口 ====================

// GetCuisines 获取所有菜系（向后兼容）
// @Summary 获取所有菜系
// @Tags tags
// @Produce json
// @Success 200 {array} TagValueResponse
// @Router /api/tags/cuisines [get]
// @Deprecated 使用 GET /api/tags?type=cuisine 替代
func (h *Handler) GetCuisines(c *gin.Context) {
	results, err := h.service.GetDistinctTagValues(models.TagTypeCuisine)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	response := make([]TagValueResponse, len(results))
	for i, r := range results {
		response[i] = TagValueResponse(r)
	}
	c.JSON(http.StatusOK, response)
}

// GetFlavors 获取所有口味（向后兼容）
// @Summary 获取所有口味
// @Tags tags
// @Produce json
// @Success 200 {array} TagValueResponse
// @Router /api/tags/flavors [get]
// @Deprecated 使用 GET /api/tags?type=flavor 替代
func (h *Handler) GetFlavors(c *gin.Context) {
	results, err := h.service.GetDistinctTagValues(models.TagTypeFlavor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	response := make([]TagValueResponse, len(results))
	for i, r := range results {
		response[i] = TagValueResponse(r)
	}
	c.JSON(http.StatusOK, response)
}

// GetScenes 获取所有场景（向后兼容）
// @Summary 获取所有场景
// @Tags tags
// @Produce json
// @Success 200 {array} TagValueResponse
// @Router /api/tags/scenes [get]
// @Deprecated 使用 GET /api/tags?type=scene 替代
func (h *Handler) GetScenes(c *gin.Context) {
	results, err := h.service.GetDistinctTagValues(models.TagTypeScene)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	response := make([]TagValueResponse, len(results))
	for i, r := range results {
		response[i] = TagValueResponse(r)
	}
	c.JSON(http.StatusOK, response)
}
