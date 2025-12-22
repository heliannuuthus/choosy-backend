package handlers

import (
	"net/http"
	"strconv"
	"time"

	"choosy-backend/internal/recommend"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RecommendHandler 推荐处理器
type RecommendHandler struct {
	service *recommend.Service
}

// NewRecommendHandler 创建推荐处理器
func NewRecommendHandler(db *gorm.DB) *RecommendHandler {
	return &RecommendHandler{
		service: recommend.NewService(db),
	}
}

type RecommendRequest struct {
	Latitude  float64 `json:"latitude" binding:"required"`
	Longitude float64 `json:"longitude" binding:"required"`
	Timestamp int64   `json:"timestamp"`
}

type RecommendResponse struct {
	Recipes     []RecipeListItem `json:"recipes"`
	Reason      string           `json:"reason"`
	Weather     *WeatherResponse `json:"weather,omitempty"`
	MealTime    string           `json:"meal_time"`
	Season      string           `json:"season"`
	Temperature string           `json:"temperature"`
}

type WeatherResponse struct {
	Temperature float64 `json:"temperature"`
	Humidity    int     `json:"humidity"`
	Weather     string  `json:"weather"`
	City        string  `json:"city,omitempty"`
}

// GetRecommendations 获取智能推荐
// @Summary 获取智能推荐菜谱
// @Description 根据地理位置、天气、时间等因素智能推荐菜谱
// @Tags recommend
// @Accept json
// @Produce json
// @Param request body RecommendRequest true "推荐请求"
// @Param limit query int false "返回数量" default(6)
// @Success 200 {object} RecommendResponse
// @Failure 400 {object} map[string]string
// @Router /api/recommend [post]
func (h *RecommendHandler) GetRecommendations(c *gin.Context) {
	var req RecommendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "缺少必要参数: latitude, longitude"})
		return
	}

	if req.Timestamp == 0 {
		req.Timestamp = time.Now().UnixMilli()
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "6"))
	if limit < 1 {
		limit = 1
	} else if limit > 20 {
		limit = 20
	}

	ctx := &recommend.Context{
		Latitude:  req.Latitude,
		Longitude: req.Longitude,
		Timestamp: req.Timestamp,
	}

	result, err := h.service.GetRecommendations(ctx, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	response := RecommendResponse{
		Recipes:     make([]RecipeListItem, len(result.Recipes)),
		Reason:      result.Reason,
		MealTime:    result.MealTime,
		Season:      result.Season,
		Temperature: result.Temperature,
	}

	if result.Weather != nil {
		response.Weather = &WeatherResponse{
			Temperature: result.Weather.Temperature,
			Humidity:    result.Weather.Humidity,
			Weather:     result.Weather.Weather,
			City:        result.Weather.City,
		}
	}

	for i, r := range result.Recipes {
		response.Recipes[i] = RecipeListItem{
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

	c.JSON(http.StatusOK, response)
}
