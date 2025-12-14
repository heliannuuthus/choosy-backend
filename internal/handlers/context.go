package handlers

import (
	"choosy-backend/internal/config"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ContextHandler 上下文处理器
type ContextHandler struct{}

func NewContextHandler() *ContextHandler {
	return &ContextHandler{}
}

// ContextRequest 上下文请求
type ContextRequest struct {
	Latitude  float64 `json:"latitude" binding:"required"`
	Longitude float64 `json:"longitude" binding:"required"`
	Timestamp int64   `json:"timestamp"` // 可选，默认当前时间
}

// LocationInfo 位置信息
type LocationInfo struct {
	Province string `json:"province"`
	City     string `json:"city"`
	District string `json:"district"`
	Adcode   string `json:"-"` // 内部使用，不返回给前端
}

// WeatherInfo 天气信息
type WeatherInfo struct {
	Temperature float64 `json:"temperature"` // 温度 (摄氏度)
	Humidity    int     `json:"humidity"`    // 湿度 (%)
	Weather     string  `json:"weather"`     // 天气状况描述
	Icon        string  `json:"icon"`        // 天气图标代码
}

// TimeInfo 时间信息
type TimeInfo struct {
	Timestamp int64  `json:"timestamp"`  // 时间戳 (毫秒)
	MealTime  string `json:"meal_time"`  // 用餐时段: breakfast/lunch/afternoon/dinner/night
	Season    string `json:"season"`     // 季节: spring/summer/autumn/winter
	DayOfWeek int    `json:"day_of_week"` // 星期几 0-6
	Hour      int    `json:"hour"`       // 小时 0-23
}

// ContextResponse 上下文响应
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

	// 默认时间为当前时间
	if req.Timestamp == 0 {
		req.Timestamp = time.Now().UnixMilli()
	}

	response := ContextResponse{}

	// 1. 获取位置信息（逆地理编码，同时获取 adcode）
	location, err := h.getLocation(req.Latitude, req.Longitude)
	if err == nil {
		response.Location = location

		// 2. 用 adcode 获取天气信息（复用逆地理编码结果）
		if location.Adcode != "" {
			weather, err := h.getWeatherByAdcode(location.Adcode)
			if err == nil {
				response.Weather = weather
			}
		}
	}

	// 3. 解析时间信息
	response.Time = h.getTimeInfo(req.Timestamp)

	c.JSON(http.StatusOK, response)
}

// getLocation 获取位置信息（高德逆地理编码）
func (h *ContextHandler) getLocation(lat, lng float64) (*LocationInfo, error) {
	amapKey := config.GetString("amap.api_key")
	if amapKey == "" {
		return nil, fmt.Errorf("未配置 amap.api_key")
	}

	url := fmt.Sprintf("https://restapi.amap.com/v3/geocode/regeo?location=%.6f,%.6f&key=%s", lng, lat, amapKey)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Status    string `json:"status"`
		Regeocode struct {
			AddressComponent struct {
				Province string `json:"province"`
				City     any    `json:"city"`
				District string `json:"district"`
				Adcode   string `json:"adcode"`
			} `json:"addressComponent"`
		} `json:"regeocode"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Status != "1" {
		return nil, fmt.Errorf("高德 API 错误")
	}

	addr := result.Regeocode.AddressComponent
	city := ""
	switch v := addr.City.(type) {
	case string:
		city = v
	}
	if city == "" {
		city = addr.Province
	}

	return &LocationInfo{
		Province: addr.Province,
		City:     city,
		District: addr.District,
		Adcode:   result.Regeocode.AddressComponent.Adcode,
	}, nil
}

// getWeatherByAdcode 根据 adcode 获取天气信息（高德天气 API）
func (h *ContextHandler) getWeatherByAdcode(adcode string) (*WeatherInfo, error) {
	amapKey := config.GetString("amap.api_key")
	if amapKey == "" {
		return nil, fmt.Errorf("未配置 amap.api_key")
	}

	url := fmt.Sprintf("https://restapi.amap.com/v3/weather/weatherInfo?city=%s&key=%s&extensions=base", adcode, amapKey)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
		Lives  []struct {
			Temperature string `json:"temperature"` // 温度
			Humidity    string `json:"humidity"`    // 湿度
			Weather     string `json:"weather"`     // 天气现象
		} `json:"lives"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Status != "1" || len(result.Lives) == 0 {
		return nil, fmt.Errorf("获取天气失败")
	}

	live := result.Lives[0]
	var temp float64
	var humidity int
	fmt.Sscanf(live.Temperature, "%f", &temp)
	fmt.Sscanf(live.Humidity, "%d", &humidity)

	return &WeatherInfo{
		Temperature: temp,
		Humidity:    humidity,
		Weather:     live.Weather,
		Icon:        "", // 高德 API 不返回图标代码
	}, nil
}

// getTimeInfo 解析时间信息
func (h *ContextHandler) getTimeInfo(timestamp int64) *TimeInfo {
	t := time.UnixMilli(timestamp)

	return &TimeInfo{
		Timestamp:  timestamp,
		MealTime:   h.getMealTime(t),
		Season:     h.getSeason(t),
		DayOfWeek:  int(t.Weekday()),
		Hour:       t.Hour(),
	}
}

// getMealTime 获取用餐时段
func (h *ContextHandler) getMealTime(t time.Time) string {
	hour := t.Hour()
	switch {
	case hour >= 5 && hour < 10:
		return "breakfast"
	case hour >= 10 && hour < 14:
		return "lunch"
	case hour >= 14 && hour < 17:
		return "afternoon"
	case hour >= 17 && hour < 21:
		return "dinner"
	default:
		return "night"
	}
}

// getSeason 获取季节
func (h *ContextHandler) getSeason(t time.Time) string {
	month := t.Month()
	switch {
	case month >= 3 && month <= 5:
		return "spring"
	case month >= 6 && month <= 8:
		return "summer"
	case month >= 9 && month <= 11:
		return "autumn"
	default:
		return "winter"
	}
}

