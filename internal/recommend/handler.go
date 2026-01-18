package recommend

import (
	"net/http"
	"strconv"
	"time"

	"zwei-backend/internal/amap"
	"zwei-backend/internal/auth"
	"zwei-backend/internal/logger"
	"zwei-backend/internal/types"
	"zwei-backend/internal/utils"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Handler 推荐处理器
type Handler struct {
	service     *Service
	rateLimiter *DailyRateLimiter
}

// NewHandler 创建推荐处理器
func NewHandler(db *gorm.DB) *Handler {
	return &Handler{
		service:     NewService(db),
		rateLimiter: NewDailyRateLimiter(10), // 每日最多 10 次
	}
}

type RecommendRequest struct {
	Latitude   float64  `json:"latitude" binding:"required"`
	Longitude  float64  `json:"longitude" binding:"required"`
	Timestamp  int64    `json:"timestamp"`
	ExcludeIDs []string `json:"exclude_ids,omitempty"` // 排除的菜谱 ID（换一批时传入已推荐的）
}

// RecommendRecipeItem 推荐菜品项（包含推荐理由）
type RecommendRecipeItem struct {
	types.RecipeListItem
	Reason string `json:"reason"` // 该菜品的推荐理由
}

type RecommendResponse struct {
	Recipes   []RecommendRecipeItem `json:"recipes"`
	Summary   string                `json:"summary"`   // LLM 生成的一句话整体评价
	Remaining int                   `json:"remaining"` // 今日剩余推荐次数
}

// GetRecommendations 获取智能推荐
// @Summary 获取智能推荐菜谱
// @Description 根据地理位置、天气、时间等因素智能推荐菜谱（基于 LLM，支持用户个性化）
// @Tags recommend
// @Accept json
// @Produce json
// @Param request body RecommendRequest true "推荐请求"
// @Param limit query int false "返回数量" default(6)
// @Success 200 {object} RecommendResponse
// @Failure 400 {object} map[string]string
// @Router /api/recommend [post]
func (h *Handler) GetRecommendations(c *gin.Context) {
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

	// 构建推荐上下文
	ctx := &Context{
		Latitude:   req.Latitude,
		Longitude:  req.Longitude,
		Timestamp:  req.Timestamp,
		ExcludeIDs: req.ExcludeIDs,
	}

	// 获取用户身份（如果已登录）
	if user, exists := c.Get("user"); exists {
		identity := user.(*auth.Identity)
		ctx.UserID = identity.GetOpenID()
	}

	// 检查每日推荐次数限制
	remaining, allowed := h.rateLimiter.Check(ctx.UserID)
	if !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"detail":    "今日推荐次数已用完，明天再来吧",
			"remaining": 0,
		})
		return
	}

	result, err := h.service.GetRecommendations(ctx, limit)
	if err != nil {
		logger.Errorf("[RecommendHandler] 获取推荐失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "服务器内部错误"})
		return
	}

	// 推荐成功，增加计数
	h.rateLimiter.Increment(ctx.UserID)

	response := RecommendResponse{
		Recipes:   make([]RecommendRecipeItem, len(result.Recipes)),
		Summary:   result.Summary,
		Remaining: remaining - 1, // 本次请求后的剩余次数
	}

	for i, r := range result.Recipes {
		response.Recipes[i] = RecommendRecipeItem{
			RecipeListItem: types.RecipeListItem{
				ID:               r.Recipe.RecipeID,
				Name:             r.Recipe.Name,
				Description:      r.Recipe.Description,
				Category:         r.Recipe.Category,
				Difficulty:       r.Recipe.Difficulty,
				Tags:             types.GroupTags(r.Recipe.Tags),
				ImagePath:        r.Recipe.GetImagePath(),
				TotalTimeMinutes: r.Recipe.TotalTimeMinutes,
			},
			Reason: r.Reason,
		}
	}

	c.JSON(http.StatusOK, response)
}

// ContextRequest 上下文请求
type ContextRequest struct {
	Latitude  float64 `json:"latitude" binding:"required"`
	Longitude float64 `json:"longitude" binding:"required"`
	Timestamp int64   `json:"timestamp"`
}

// LocationInfo 位置信息
type LocationInfo struct {
	Province string `json:"province"`
	City     string `json:"city"`
	District string `json:"district"`
	Adcode   string `json:"-"`
}

// TimeInfo 时间信息
type TimeInfo struct {
	Timestamp int64  `json:"timestamp"`
	MealTime  string `json:"meal_time"`
	Season    string `json:"season"`
	DayOfWeek int    `json:"day_of_week"`
	Hour      int    `json:"hour"`
}

// ContextResponse 上下文响应
type ContextResponse struct {
	Location *LocationInfo        `json:"location"`
	Weather  *WeatherInfoResponse `json:"weather"`
	Time     *TimeInfo            `json:"time"`
}

// GetContext 获取推荐上下文信息
// @Summary 获取推荐上下文
// @Description 根据经纬度获取位置、天气、时间信息
// @Tags recommend
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ContextRequest true "上下文请求"
// @Success 200 {object} ContextResponse
// @Failure 400 {object} map[string]string
// @Router /api/recommend/context [post]
func (h *Handler) GetContext(c *gin.Context) {
	var req ContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少必要参数: latitude, longitude"})
		return
	}

	if req.Timestamp == 0 {
		req.Timestamp = time.Now().UnixMilli()
	}

	response := ContextResponse{}

	logger.Debug("获取位置", zap.Float64("lat", req.Latitude), zap.Float64("lng", req.Longitude))
	amapClient := amap.GetClient()
	location, err := amapClient.GetLocation(req.Latitude, req.Longitude)
	if err != nil {
		logger.Error("高德逆地理编码失败", zap.Error(err), zap.Float64("lat", req.Latitude), zap.Float64("lng", req.Longitude))
	} else {
		response.Location = &LocationInfo{
			Province: location.Province,
			City:     location.City,
			District: location.District,
			Adcode:   location.Adcode,
		}

		if location.Adcode != "" {
			weather, err := amapClient.GetWeatherByAdcode(location.Adcode)
			if err == nil {
				response.Weather = &WeatherInfoResponse{
					Temperature: weather.Temperature,
					Humidity:    weather.Humidity,
					Weather:     weather.Weather,
					Icon:        "", // 高德 API 可能不返回 icon，需要根据 weather 字段生成
				}
			}
		}
	}

	t := time.UnixMilli(req.Timestamp)
	response.Time = &TimeInfo{
		Timestamp: req.Timestamp,
		MealTime:  utils.GetMealTime(t),
		Season:    utils.GetSeason(t),
		DayOfWeek: int(t.Weekday()),
		Hour:      t.Hour(),
	}

	c.JSON(http.StatusOK, response)
}
