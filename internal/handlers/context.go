package handlers

import (
	"net/http"
	"time"

	"choosy-backend/internal/amap"
	"choosy-backend/internal/utils"

	"github.com/gin-gonic/gin"
)

// ContextHandler 上下文处理器
type ContextHandler struct {
	amap *amap.Client
}

func NewContextHandler() *ContextHandler {
	return &ContextHandler{
		amap: amap.GetClient(),
	}
}

type ContextRequest struct {
	Latitude  float64 `json:"latitude" binding:"required"`
	Longitude float64 `json:"longitude" binding:"required"`
	Timestamp int64   `json:"timestamp"`
}

type LocationInfo struct {
	Province string `json:"province"`
	City     string `json:"city"`
	District string `json:"district"`
	Adcode   string `json:"-"`
}

type WeatherInfo struct {
	Temperature float64 `json:"temperature"`
	Humidity    int     `json:"humidity"`
	Weather     string  `json:"weather"`
	Icon        string  `json:"icon"`
}

type TimeInfo struct {
	Timestamp int64  `json:"timestamp"`
	MealTime  string `json:"meal_time"`
	Season    string `json:"season"`
	DayOfWeek int    `json:"day_of_week"`
	Hour      int    `json:"hour"`
}

type ContextResponse struct {
	Location *LocationInfo `json:"location"`
	Weather  *WeatherInfo  `json:"weather"`
	Time     *TimeInfo     `json:"time"`
}

// GetContext 获取推荐上下文信息
// @Summary 获取推荐上下文
// @Description 根据经纬度获取位置、天气、时间信息
// @Tags context
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ContextRequest true "上下文请求"
// @Success 200 {object} ContextResponse
// @Failure 400 {object} map[string]string
// @Router /api/context [post]
func (h *ContextHandler) GetContext(c *gin.Context) {
	var req ContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少必要参数: latitude, longitude"})
		return
	}

	if req.Timestamp == 0 {
		req.Timestamp = time.Now().UnixMilli()
	}

	response := ContextResponse{}

	location, err := h.amap.GetLocation(req.Latitude, req.Longitude)
	if err == nil {
		response.Location = &LocationInfo{
			Province: location.Province,
			City:     location.City,
			District: location.District,
			Adcode:   location.Adcode,
		}

		if location.Adcode != "" {
			weather, err := h.amap.GetWeatherByAdcode(location.Adcode)
			if err == nil {
				response.Weather = &WeatherInfo{
					Temperature: weather.Temperature,
					Humidity:    weather.Humidity,
					Weather:     weather.Weather,
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
