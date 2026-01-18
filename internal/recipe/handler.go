package recipe

import (
	"net/http"
	"strconv"

	"zwei-backend/internal/models"
	"zwei-backend/internal/types"
	"zwei-backend/internal/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Handler 菜谱处理器
type Handler struct {
	service *Service
}

// NewHandler 创建菜谱处理器
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		service: NewService(db),
	}
}

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

type IngredientRequest struct {
	Name         string   `json:"name" binding:"required"`
	Quantity     *float64 `json:"quantity"`
	Unit         *string  `json:"unit"`
	TextQuantity string   `json:"text_quantity" binding:"required"`
	Notes        *string  `json:"notes"`
}

type StepRequest struct {
	Step        int    `json:"step" binding:"required"`
	Description string `json:"description" binding:"required"`
}

type RecipeCreateRequest struct {
	ID               string              `json:"id"`
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

type RecipeResponse struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	Description      *string              `json:"description"`
	Images           []string             `json:"images"`
	ImagePath        *string              `json:"image_path"`
	Category         string               `json:"category"`
	Difficulty       int                  `json:"difficulty"`
	Tags             types.TagsGrouped    `json:"tags"`
	Servings         int                  `json:"servings"`
	PrepTimeMinutes  *int                 `json:"prep_time_minutes"`
	CookTimeMinutes  *int                 `json:"cook_time_minutes"`
	TotalTimeMinutes *int                 `json:"total_time_minutes"`
	Ingredients      []IngredientResponse `json:"ingredients"`
	Steps            []StepResponse       `json:"steps"`
	AdditionalNotes  []string             `json:"additional_notes"`
}

type IngredientResponse struct {
	ID           uint     `json:"id"`
	Name         string   `json:"name"`
	Category     *string  `json:"category"`
	Quantity     *float64 `json:"quantity"`
	Unit         *string  `json:"unit"`
	TextQuantity string   `json:"text_quantity"`
	Notes        *string  `json:"notes"`
}

type StepResponse struct {
	ID          uint   `json:"id"`
	Step        int    `json:"step"`
	Description string `json:"description"`
}

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
func (h *Handler) CreateRecipe(c *gin.Context) {
	var req RecipeCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	recipeID := req.ID
	if recipeID == "" {
		recipeID = utils.GenerateRecipeID()
	}

	recipeModel := models.Recipe{
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

	if err := h.service.CreateRecipe(&recipeModel, ingredients, steps, req.AdditionalNotes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

	createdRecipe, _ := h.service.GetRecipe(recipeModel.RecipeID)
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
// @Success 200 {array} types.RecipeListItem
// @Router /api/recipes [get]
func (h *Handler) GetRecipes(c *gin.Context) {
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
func (h *Handler) GetRecipe(c *gin.Context) {
	id := c.Param("recipe_id")

	recipeModel, err := h.service.GetRecipe(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	if recipeModel == nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "菜谱 ID '" + id + "' 不存在"})
		return
	}

	c.JSON(http.StatusOK, h.toRecipeResponse(recipeModel))
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
func (h *Handler) UpdateRecipe(c *gin.Context) {
	id := c.Param("recipe_id")

	var req RecipeUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}

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

	var notes []string
	if req.AdditionalNotes != nil {
		notes = *req.AdditionalNotes
	}

	recipeModel, err := h.service.UpdateRecipe(
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

	updatedRecipe, _ := h.service.GetRecipe(id)
	if updatedRecipe != nil {
		recipeModel = updatedRecipe
	}

	c.JSON(http.StatusOK, h.toRecipeResponse(recipeModel))
}

// DeleteRecipe 删除菜谱
// @Summary 删除菜谱
// @Tags recipes
// @Param recipe_id path string true "菜谱ID"
// @Success 204
// @Failure 404 {object} map[string]string
// @Router /api/recipes/{recipe_id} [delete]
func (h *Handler) DeleteRecipe(c *gin.Context) {
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
func (h *Handler) GetCategories(c *gin.Context) {
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
func (h *Handler) CreateRecipesBatch(c *gin.Context) {
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

	responses := make([]RecipeResponse, len(created))
	for i, r := range created {
		recipeModel, _ := h.service.GetRecipe(r.RecipeID)
		if recipeModel != nil {
			responses[i] = *h.toRecipeResponse(recipeModel)
		}
	}

	c.JSON(http.StatusCreated, responses)
}

func (h *Handler) toRecipeResponse(r *models.Recipe) *RecipeResponse {
	if r == nil {
		return nil
	}

	ingredients := make([]IngredientResponse, len(r.Ingredients))
	for i, ing := range r.Ingredients {
		ingredients[i] = IngredientResponse{
			ID:           ing.ID,
			Name:         ing.Name,
			Category:     ing.Category,
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

	tags := types.GroupTags(r.Tags)

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
