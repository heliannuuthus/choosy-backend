package handlers

import (
	"net/http"
	"strconv"
	"time"

	"choosy-backend/internal/services"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RecommendHandler 推荐处理器
type RecommendHandler struct {
	service *services.RecommendService
}

// NewRecommendHandler 创建推荐处理器
func NewRecommendHandler(db *gorm.DB) *RecommendHandler {
	return &RecommendHandler{
		service: services.NewRecommendService(db),
	}
}

// RecommendRequest 推荐请求
type RecommendRequest struct {
	Latitude  float64 `json:"latitude" binding:"required"`  // 纬度
	Longitude float64 `json:"longitude" binding:"required"` // 经度
	Timestamp int64   `json:"timestamp"`                    // 时间戳 (毫秒)，可选
}

// RecommendResponse 推荐响应
type RecommendResponse struct {
	Recipes     []RecipeListItem `json:"recipes"`
	Reason      string           `json:"reason"`
	Weather     *WeatherResponse `json:"weather,omitempty"`
	MealTime    string           `json:"meal_time"`
	Season      string           `json:"season"`
	Temperature string           `json:"temperature"`
}

// WeatherResponse 天气响应
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

	// 默认时间为当前时间
	if req.Timestamp == 0 {
		req.Timestamp = time.Now().UnixMilli()
	}

	// 获取 limit 参数
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "6"))
	if limit < 1 {
		limit = 1
	} else if limit > 20 {
		limit = 20
	}

	// 构建推荐上下文
	ctx := &services.RecommendContext{
		Latitude:  req.Latitude,
		Longitude: req.Longitude,
		Timestamp: req.Timestamp,
	}

	// 获取推荐结果
	result, err := h.service.GetRecommendations(ctx, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	// 转换响应格式
	response := RecommendResponse{
		Recipes:     make([]RecipeListItem, len(result.Recipes)),
		Reason:      result.Reason,
		MealTime:    result.MealTime,
		Season:      result.Season,
		Temperature: result.Temperature,
	}

	// 转换天气信息
	if result.Weather != nil {
		response.Weather = &WeatherResponse{
			Temperature: result.Weather.Temperature,
			Humidity:    result.Weather.Humidity,
			Weather:     result.Weather.Weather,
			City:        result.Weather.City,
		}
	}

	// 转换菜谱列表
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
