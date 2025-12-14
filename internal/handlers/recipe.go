package handlers

import (
	"net/http"
	"strconv"

	"choosy-backend/internal/models"
	"choosy-backend/internal/services"
	"choosy-backend/internal/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RecipeHandler 菜谱处理器
type RecipeHandler struct {
	service *services.RecipeService
}

// NewRecipeHandler 创建菜谱处理器
func NewRecipeHandler(db *gorm.DB) *RecipeHandler {
	return &RecipeHandler{
		service: services.NewRecipeService(db),
	}
}

// 分类中文名称映射
var categoryNames = map[string]string{
	"aquatic":        "水产",
	"breakfast":      "早餐",
	"condiment":      "调味品",
	"drink":          "饮品",
	"meat_dish":      "肉类",
	"semi-finished":  "半成品",
	"soup":           "汤类",
	"staple":         "主食",
	"vegetable_dish": "素菜",
}

// IngredientRequest 食材请求
type IngredientRequest struct {
	Name         string   `json:"name" binding:"required"`
	Quantity     *float64 `json:"quantity"`
	Unit         *string  `json:"unit"`
	TextQuantity string   `json:"text_quantity" binding:"required"`
	Notes        *string  `json:"notes"`
}

// StepRequest 步骤请求
type StepRequest struct {
	Step        int    `json:"step" binding:"required"`
	Description string `json:"description" binding:"required"`
}

// RecipeCreateRequest 创建菜谱请求
type RecipeCreateRequest struct {
	ID               string              `json:"id"` // 可选，不提供则自动生成
	Name             string              `json:"name" binding:"required"`
	Description      *string             `json:"description"`
	Images           []string            `json:"images"`
	Category         string              `json:"category" binding:"required"`
	Difficulty       int                 `json:"difficulty" binding:"required"`
	Tags             []string            `json:"tags"`
	Servings         int                 `json:"servings" binding:"required"`
	PrepTimeMinutes  *int                `json:"prep_time_minutes"`
	CookTimeMinutes  *int                `json:"cook_time_minutes"`
	TotalTimeMinutes *int                `json:"total_time_minutes"`
	Ingredients      []IngredientRequest `json:"ingredients"`
	Steps            []StepRequest       `json:"steps"`
	AdditionalNotes  []string            `json:"additional_notes"`
}

// RecipeUpdateRequest 更新菜谱请求
type RecipeUpdateRequest struct {
	Name             *string              `json:"name"`
	Description      *string              `json:"description"`
	Images           *[]string            `json:"images"`
	Category         *string              `json:"category"`
	Difficulty       *int                 `json:"difficulty"`
	Tags             *[]string            `json:"tags"`
	Servings         *int                 `json:"servings"`
	PrepTimeMinutes  *int                 `json:"prep_time_minutes"`
	CookTimeMinutes  *int                 `json:"cook_time_minutes"`
	TotalTimeMinutes *int                 `json:"total_time_minutes"`
	Ingredients      *[]IngredientRequest `json:"ingredients"`
	Steps            *[]StepRequest       `json:"steps"`
	AdditionalNotes  *[]string            `json:"additional_notes"`
}

// TagsGrouped 分组的标签
type TagsGrouped struct {
	Cuisines []string `json:"cuisines"`
	Flavors  []string `json:"flavors"`
	Scenes   []string `json:"scenes"`
}

// RecipeListItem 菜谱列表项
type RecipeListItem struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	Description      *string      `json:"description"`
	Category         string       `json:"category"`
	Difficulty       int          `json:"difficulty"`
	Tags             TagsGrouped  `json:"tags"`
	ImagePath        *string      `json:"image_path"`
	TotalTimeMinutes *int         `json:"total_time_minutes"`
}

// RecipeResponse 菜谱响应
type RecipeResponse struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	Description      *string              `json:"description"`
	Images           []string             `json:"images"`
	ImagePath        *string              `json:"image_path"` // images[0]，兼容前端
	Category         string               `json:"category"`
	Difficulty       int                  `json:"difficulty"`
	Tags             TagsGrouped          `json:"tags"`
	Servings         int                  `json:"servings"`
	PrepTimeMinutes  *int                 `json:"prep_time_minutes"`
	CookTimeMinutes  *int                 `json:"cook_time_minutes"`
	TotalTimeMinutes *int                 `json:"total_time_minutes"`
	Ingredients      []IngredientResponse `json:"ingredients"`
	Steps            []StepResponse       `json:"steps"`
	AdditionalNotes  []string             `json:"additional_notes"`
}

// IngredientResponse 食材响应
type IngredientResponse struct {
	ID           uint     `json:"id"`
	Name         string   `json:"name"`
	Quantity     *float64 `json:"quantity"`
	Unit         *string  `json:"unit"`
	TextQuantity string   `json:"text_quantity"`
	Notes        *string  `json:"notes"`
}

// StepResponse 步骤响应
type StepResponse struct {
	ID          uint   `json:"id"`
	Step        int    `json:"step"`
	Description string `json:"description"`
}

// CategoryResponse 分类响应
type CategoryResponse struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// CreateRecipe 创建菜谱
// @Summary 创建新菜谱
// @Tags recipes
// @Accept json
// @Produce json
// @Param recipe body RecipeCreateRequest true "菜谱信息"
// @Success 201 {object} RecipeResponse
// @Failure 400 {object} map[string]string
// @Router /api/recipes [post]
func (h *RecipeHandler) CreateRecipe(c *gin.Context) {
	var req RecipeCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	// 自动生成 ID（如果未提供）
	recipeID := req.ID
	if recipeID == "" {
		recipeID = utils.GenerateRecipeID()
	}

	// 转换为模型 (Tags 通过关联表管理，不在这里设置)
	recipe := models.Recipe{
		RecipeID:         recipeID,
		Name:             req.Name,
		Description:      req.Description,
		Images:           req.Images,
		Category:         req.Category,
		Difficulty:       req.Difficulty,
		Servings:         req.Servings,
		PrepTimeMinutes:  req.PrepTimeMinutes,
		CookTimeMinutes:  req.CookTimeMinutes,
		TotalTimeMinutes: req.TotalTimeMinutes,
	}

	ingredients := make([]models.Ingredient, len(req.Ingredients))
	for i, ing := range req.Ingredients {
		ingredients[i] = models.Ingredient{
			Name:         ing.Name,
			Quantity:     ing.Quantity,
			Unit:         ing.Unit,
			TextQuantity: ing.TextQuantity,
			Notes:        ing.Notes,
		}
	}

	steps := make([]models.Step, len(req.Steps))
	for i, step := range req.Steps {
		steps[i] = models.Step{
			Step:        step.Step,
			Description: step.Description,
		}
	}

	if err := h.service.CreateRecipe(&recipe, ingredients, steps, req.AdditionalNotes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	// 重新获取完整的菜谱
	createdRecipe, _ := h.service.GetRecipe(recipe.RecipeID)
	c.JSON(http.StatusCreated, h.toRecipeResponse(createdRecipe))
}

// GetRecipes 获取菜谱列表
// @Summary 获取菜谱列表
// @Tags recipes
// @Produce json
// @Param category query string false "分类"
// @Param search query string false "搜索关键词"
// @Param limit query int false "限制数量" default(100)
// @Param offset query int false "偏移量" default(0)
// @Success 200 {array} RecipeListItem
// @Router /api/recipes [get]
func (h *RecipeHandler) GetRecipes(c *gin.Context) {
	category := c.Query("category")
	search := c.Query("search")

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if limit < 1 {
		limit = 1
	} else if limit > 500 {
		limit = 500
	}

	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if offset < 0 {
		offset = 0
	}

	recipes, err := h.service.GetRecipes(category, search, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	// 转换为列表项
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

	c.JSON(http.StatusOK, items)
}

// GetRecipe 获取菜谱详情
// @Summary 获取菜谱详情
// @Tags recipes
// @Produce json
// @Param recipe_id path string true "菜谱ID"
// @Success 200 {object} RecipeResponse
// @Failure 404 {object} map[string]string
// @Router /api/recipes/{recipe_id} [get]
func (h *RecipeHandler) GetRecipe(c *gin.Context) {
	id := c.Param("recipe_id")

	recipe, err := h.service.GetRecipe(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	if recipe == nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "菜谱 ID '" + id + "' 不存在"})
		return
	}

	c.JSON(http.StatusOK, h.toRecipeResponse(recipe))
}

// UpdateRecipe 更新菜谱
// @Summary 更新菜谱
// @Tags recipes
// @Accept json
// @Produce json
// @Param recipe_id path string true "菜谱ID"
// @Param recipe body RecipeUpdateRequest true "更新内容"
// @Success 200 {object} RecipeResponse
// @Failure 404 {object} map[string]string
// @Router /api/recipes/{recipe_id} [put]
func (h *RecipeHandler) UpdateRecipe(c *gin.Context) {
	id := c.Param("recipe_id")

	var req RecipeUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	// 构建更新字段
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Images != nil {
		updates["images"] = models.StringSlice(*req.Images)
	}
	if req.Category != nil {
		updates["category"] = *req.Category
	}
	if req.Difficulty != nil {
		updates["difficulty"] = *req.Difficulty
	}
	// Tags 通过关联表管理，暂不支持通过 API 更新
	if req.Servings != nil {
		updates["servings"] = *req.Servings
	}
	if req.PrepTimeMinutes != nil {
		updates["prep_time_minutes"] = *req.PrepTimeMinutes
	}
	if req.CookTimeMinutes != nil {
		updates["cook_time_minutes"] = *req.CookTimeMinutes
	}
	if req.TotalTimeMinutes != nil {
		updates["total_time_minutes"] = *req.TotalTimeMinutes
	}

	// 转换食材
	var ingredients []models.Ingredient
	if req.Ingredients != nil {
		ingredients = make([]models.Ingredient, len(*req.Ingredients))
		for i, ing := range *req.Ingredients {
			ingredients[i] = models.Ingredient{
				Name:         ing.Name,
				Quantity:     ing.Quantity,
				Unit:         ing.Unit,
				TextQuantity: ing.TextQuantity,
				Notes:        ing.Notes,
			}
		}
	}

	// 转换步骤
	var steps []models.Step
	if req.Steps != nil {
		steps = make([]models.Step, len(*req.Steps))
		for i, step := range *req.Steps {
			steps[i] = models.Step{
				Step:        step.Step,
				Description: step.Description,
			}
		}
	}

	// 小贴士
	var notes []string
	if req.AdditionalNotes != nil {
		notes = *req.AdditionalNotes
	}

	recipe, err := h.service.UpdateRecipe(
		id,
		updates,
		ingredients,
		steps,
		notes,
		req.Ingredients != nil,
		req.Steps != nil,
		req.AdditionalNotes != nil,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": err.Error()})
		return
	}

	// 重新获取完整的菜谱
	updatedRecipe, _ := h.service.GetRecipe(id)
	if updatedRecipe != nil {
		recipe = updatedRecipe
	}

	c.JSON(http.StatusOK, h.toRecipeResponse(recipe))
}

// DeleteRecipe 删除菜谱
// @Summary 删除菜谱
// @Tags recipes
// @Param recipe_id path string true "菜谱ID"
// @Success 204
// @Failure 404 {object} map[string]string
// @Router /api/recipes/{recipe_id} [delete]
func (h *RecipeHandler) DeleteRecipe(c *gin.Context) {
	id := c.Param("recipe_id")

	if err := h.service.DeleteRecipe(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetCategories 获取所有分类
// @Summary 获取所有分类
// @Tags recipes
// @Produce json
// @Success 200 {array} CategoryResponse
// @Router /api/recipes/categories/list [get]
func (h *RecipeHandler) GetCategories(c *gin.Context) {
	categories, err := h.service.GetCategories()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	result := make([]CategoryResponse, len(categories))
	for i, key := range categories {
		label := key
		if name, ok := categoryNames[key]; ok {
			label = name
		}
		result[i] = CategoryResponse{
			Key:   key,
			Label: label,
		}
	}

	c.JSON(http.StatusOK, result)
}

// CreateRecipesBatch 批量创建菜谱
// @Summary 批量创建菜谱
// @Tags recipes
// @Accept json
// @Produce json
// @Param recipes body []RecipeCreateRequest true "菜谱列表"
// @Success 201 {array} RecipeResponse
// @Router /api/recipes/batch [post]
func (h *RecipeHandler) CreateRecipesBatch(c *gin.Context) {
	var reqs []RecipeCreateRequest
	if err := c.ShouldBindJSON(&reqs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	recipes := make([]models.Recipe, len(reqs))
	ingredientsList := make([][]models.Ingredient, len(reqs))
	stepsList := make([][]models.Step, len(reqs))
	notesList := make([][]string, len(reqs))

	for i, req := range reqs {
		recipeID := req.ID
		if recipeID == "" {
			recipeID = utils.GenerateRecipeID()
		}
		recipes[i] = models.Recipe{
			RecipeID:         recipeID,
			Name:             req.Name,
			Description:      req.Description,
			Images:           req.Images,
			Category:         req.Category,
			Difficulty:       req.Difficulty,
			Servings:         req.Servings,
			PrepTimeMinutes:  req.PrepTimeMinutes,
			CookTimeMinutes:  req.CookTimeMinutes,
			TotalTimeMinutes: req.TotalTimeMinutes,
		}

		ingredients := make([]models.Ingredient, len(req.Ingredients))
		for j, ing := range req.Ingredients {
			ingredients[j] = models.Ingredient{
				Name:         ing.Name,
				Quantity:     ing.Quantity,
				Unit:         ing.Unit,
				TextQuantity: ing.TextQuantity,
				Notes:        ing.Notes,
			}
		}
		ingredientsList[i] = ingredients

		steps := make([]models.Step, len(req.Steps))
		for j, step := range req.Steps {
			steps[j] = models.Step{
				Step:        step.Step,
				Description: step.Description,
			}
		}
		stepsList[i] = steps

		notesList[i] = req.AdditionalNotes
	}

	created, err := h.service.CreateRecipesBatch(recipes, ingredientsList, stepsList, notesList)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	// 转换响应
	responses := make([]RecipeResponse, len(created))
	for i, r := range created {
		recipe, _ := h.service.GetRecipe(r.RecipeID)
		if recipe != nil {
			responses[i] = *h.toRecipeResponse(recipe)
		}
	}

	c.JSON(http.StatusCreated, responses)
}

// GroupTags 将 []models.Tag 按类型分组
func GroupTags(tags []models.Tag) TagsGrouped {
	result := TagsGrouped{
		Cuisines: []string{},
		Flavors:  []string{},
		Scenes:   []string{},
	}
	for _, t := range tags {
		switch t.Type {
		case models.TagTypeCuisine:
			result.Cuisines = append(result.Cuisines, t.Label)
		case models.TagTypeFlavor:
			result.Flavors = append(result.Flavors, t.Label)
		case models.TagTypeScene:
			result.Scenes = append(result.Scenes, t.Label)
		}
	}
	return result
}

// toRecipeResponse 转换为响应格式
func (h *RecipeHandler) toRecipeResponse(r *models.Recipe) *RecipeResponse {
	if r == nil {
		return nil
	}

	ingredients := make([]IngredientResponse, len(r.Ingredients))
	for i, ing := range r.Ingredients {
		ingredients[i] = IngredientResponse{
			ID:           ing.ID,
			Name:         ing.Name,
			Quantity:     ing.Quantity,
			Unit:         ing.Unit,
			TextQuantity: ing.TextQuantity,
			Notes:        ing.Notes,
		}
	}

	steps := make([]StepResponse, len(r.Steps))
	for i, step := range r.Steps {
		steps[i] = StepResponse{
			ID:          step.ID,
			Step:        step.Step,
			Description: step.Description,
		}
	}

	notes := make([]string, len(r.AdditionalNotes))
	for i, note := range r.AdditionalNotes {
		notes[i] = note.Note
	}

	images := r.Images
	if images == nil {
		images = []string{}
	}

	tags := GroupTags(r.Tags)

	return &RecipeResponse{
		ID:               r.RecipeID,
		Name:             r.Name,
		Description:      r.Description,
		Images:           images,
		ImagePath:        r.GetImagePath(),
		Category:         r.Category,
		Difficulty:       r.Difficulty,
		Tags:             tags,
		Servings:         r.Servings,
		PrepTimeMinutes:  r.PrepTimeMinutes,
		CookTimeMinutes:  r.CookTimeMinutes,
		TotalTimeMinutes: r.TotalTimeMinutes,
		Ingredients:      ingredients,
		Steps:            steps,
		AdditionalNotes:  notes,
	}
}
