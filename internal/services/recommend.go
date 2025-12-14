package services

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"choosy-backend/internal/config"
	"choosy-backend/internal/models"

	"gorm.io/gorm"
)

// RecommendService 推荐服务
type RecommendService struct {
	db           *gorm.DB
	tagService   *TagService
	weatherCache map[string]*CachedWeather // 简单缓存
}

// CachedWeather 缓存的天气数据
type CachedWeather struct {
	Data      *WeatherInfo
	ExpiresAt time.Time
}

// WeatherInfo 天气信息
type WeatherInfo struct {
	Temperature float64 `json:"temperature"` // 温度 (摄氏度)
	Humidity    int     `json:"humidity"`    // 湿度 (%)
	Weather     string  `json:"weather"`     // 天气状况
	WeatherCode string  `json:"weather_code"`
	City        string  `json:"city"`
}

// RecommendContext 推荐上下文
type RecommendContext struct {
	Latitude  float64 `json:"latitude"`  // 纬度
	Longitude float64 `json:"longitude"` // 经度
	Timestamp int64   `json:"timestamp"` // 时间戳 (毫秒)
}

// RecommendResult 推荐结果
type RecommendResult struct {
	Recipes     []models.Recipe `json:"recipes"`
	Reason      string          `json:"reason"`      // 推荐理由
	Weather     *WeatherInfo    `json:"weather"`     // 天气信息
	MealTime    string          `json:"meal_time"`   // 用餐时段
	Season      string          `json:"season"`      // 季节
	Temperature string          `json:"temperature"` // 温度感受 (cold/cool/warm/hot)
}

// NewRecommendService 创建推荐服务
func NewRecommendService(db *gorm.DB) *RecommendService {
	return &RecommendService{
		db:           db,
		tagService:   NewTagService(db),
		weatherCache: make(map[string]*CachedWeather),
	}
}

// GetRecommendations 获取推荐菜谱
func (s *RecommendService) GetRecommendations(ctx *RecommendContext, limit int) (*RecommendResult, error) {
	result := &RecommendResult{}

	// 1. 获取天气信息
	weather, err := s.getWeather(ctx.Latitude, ctx.Longitude)
	if err != nil {
		// 天气获取失败不影响推荐，使用默认值
		weather = &WeatherInfo{Temperature: 20, Weather: "晴"}
	}
	result.Weather = weather

	// 2. 解析时间信息
	t := time.UnixMilli(ctx.Timestamp)
	result.MealTime = s.getMealTime(t)
	result.Season = s.getSeason(t)
	result.Temperature = s.getTemperatureFeeling(weather.Temperature)

	// 3. 根据上下文构建推荐条件
	conditions := s.buildRecommendConditions(result)

	// 4. 查询符合条件的菜谱
	recipes, err := s.queryRecipes(conditions, limit)
	if err != nil {
		return nil, err
	}
	result.Recipes = recipes

	// 5. 生成推荐理由
	result.Reason = s.generateReason(result)

	return result, nil
}

// getWeather 获取天气信息 (使用和风天气 API)
func (s *RecommendService) getWeather(lat, lon float64) (*WeatherInfo, error) {
	// 检查缓存 (按经纬度精确到 0.1 度缓存)
	cacheKey := fmt.Sprintf("%.1f,%.1f", lat, lon)
	if cached, ok := s.weatherCache[cacheKey]; ok {
		if time.Now().Before(cached.ExpiresAt) {
			return cached.Data, nil
		}
	}

	apiKey := config.GetString("weather.api_key")
	if apiKey == "" {
		return nil, fmt.Errorf("weather API key not configured")
	}

	// 和风天气 API
	url := fmt.Sprintf(
		"https://devapi.qweather.com/v7/weather/now?location=%.2f,%.2f&key=%s",
		lon, lat, apiKey,
	)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp struct {
		Code string `json:"code"`
		Now  struct {
			Temp     string `json:"temp"`
			Humidity string `json:"humidity"`
			Text     string `json:"text"`
			Icon     string `json:"icon"`
		} `json:"now"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	if apiResp.Code != "200" {
		return nil, fmt.Errorf("weather API error: %s", apiResp.Code)
	}

	var temp float64
	var humidity int
	fmt.Sscanf(apiResp.Now.Temp, "%f", &temp)
	fmt.Sscanf(apiResp.Now.Humidity, "%d", &humidity)

	weather := &WeatherInfo{
		Temperature: temp,
		Humidity:    humidity,
		Weather:     apiResp.Now.Text,
		WeatherCode: apiResp.Now.Icon,
	}

	// 缓存 30 分钟
	s.weatherCache[cacheKey] = &CachedWeather{
		Data:      weather,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	return weather, nil
}

// getMealTime 获取用餐时段
func (s *RecommendService) getMealTime(t time.Time) string {
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
		return "midnight"
	}
}

// getSeason 获取季节
func (s *RecommendService) getSeason(t time.Time) string {
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

// getTemperatureFeeling 获取温度感受
func (s *RecommendService) getTemperatureFeeling(temp float64) string {
	switch {
	case temp < 5:
		return "cold"
	case temp < 15:
		return "cool"
	case temp < 25:
		return "warm"
	default:
		return "hot"
	}
}

// RecommendConditions 推荐条件
type RecommendConditions struct {
	PreferredFlavors []string // 偏好口味
	PreferredScenes  []string // 偏好场景
	ExcludedFlavors  []string // 排除口味
	DifficultyMax    int      // 最大难度
}

// buildRecommendConditions 根据上下文构建推荐条件
func (s *RecommendService) buildRecommendConditions(result *RecommendResult) *RecommendConditions {
	cond := &RecommendConditions{
		DifficultyMax: 5,
	}

	// 根据温度调整
	switch result.Temperature {
	case "cold":
		// 冷天推荐热食、滋补
		cond.PreferredFlavors = append(cond.PreferredFlavors, "warm", "nourishing", "savory")
		cond.PreferredScenes = append(cond.PreferredScenes, "winter", "home_cooking")
	case "cool":
		cond.PreferredFlavors = append(cond.PreferredFlavors, "savory", "mild")
	case "warm":
		cond.PreferredFlavors = append(cond.PreferredFlavors, "fresh", "light")
	case "hot":
		// 热天推荐清淡、凉菜
		cond.PreferredFlavors = append(cond.PreferredFlavors, "light", "fresh", "sour", "cool")
		cond.PreferredScenes = append(cond.PreferredScenes, "summer", "light_meal")
		cond.ExcludedFlavors = append(cond.ExcludedFlavors, "heavy", "greasy")
	}

	// 根据用餐时段调整
	switch result.MealTime {
	case "breakfast":
		cond.PreferredScenes = append(cond.PreferredScenes, "breakfast", "quick")
		cond.DifficultyMax = 3 // 早餐简单点
	case "lunch":
		cond.PreferredScenes = append(cond.PreferredScenes, "lunch", "quick")
	case "afternoon":
		cond.PreferredScenes = append(cond.PreferredScenes, "snack", "light_meal")
	case "dinner":
		cond.PreferredScenes = append(cond.PreferredScenes, "dinner", "home_cooking")
	case "midnight":
		cond.PreferredScenes = append(cond.PreferredScenes, "midnight_snack", "quick")
		cond.DifficultyMax = 3
	}

	// 根据天气调整
	if result.Weather != nil {
		weather := result.Weather.Weather
		switch {
		case contains(weather, "雨"):
			cond.PreferredScenes = append(cond.PreferredScenes, "home_cooking", "comfort_food")
			cond.PreferredFlavors = append(cond.PreferredFlavors, "warm")
		case contains(weather, "雪"):
			cond.PreferredFlavors = append(cond.PreferredFlavors, "warm", "nourishing")
		}
	}

	// 根据季节调整
	switch result.Season {
	case "spring":
		cond.PreferredFlavors = append(cond.PreferredFlavors, "fresh", "light")
	case "summer":
		cond.PreferredFlavors = append(cond.PreferredFlavors, "cool", "light")
	case "autumn":
		cond.PreferredFlavors = append(cond.PreferredFlavors, "nourishing")
		cond.PreferredScenes = append(cond.PreferredScenes, "autumn")
	case "winter":
		cond.PreferredFlavors = append(cond.PreferredFlavors, "warm", "nourishing")
		cond.PreferredScenes = append(cond.PreferredScenes, "winter")
	}

	return cond
}

// queryRecipes 根据条件查询菜谱
func (s *RecommendService) queryRecipes(cond *RecommendConditions, limit int) ([]models.Recipe, error) {
	// 构建标签查询条件
	var preferredTags []string
	preferredTags = append(preferredTags, cond.PreferredFlavors...)
	preferredTags = append(preferredTags, cond.PreferredScenes...)

	// 查询有这些标签的菜谱 ID（按匹配数量排序）
	var recipeCounts []struct {
		RecipeID string
		Count    int
	}

	if len(preferredTags) > 0 {
		err := s.db.Table("tags").
			Select("recipe_id, COUNT(*) as count").
			Where("value IN ?", preferredTags).
			Group("recipe_id").
			Order("count DESC").
			Limit(limit * 3). // 多查一些用于筛选
			Find(&recipeCounts).Error
		if err != nil {
			return nil, err
		}
	}

	var recipeIDs []string
	for _, rc := range recipeCounts {
		recipeIDs = append(recipeIDs, rc.RecipeID)
	}

	// 如果没有匹配的标签，随机获取
	if len(recipeIDs) == 0 {
		err := s.db.Model(&models.Recipe{}).
			Select("recipe_id").
			Order("RANDOM()").
			Limit(limit*2).
			Pluck("recipe_id", &recipeIDs).Error
		if err != nil {
			return nil, err
		}
	}

	// 查询菜谱详情
	query := s.db.Model(&models.Recipe{}).
		Where("recipe_id IN ?", recipeIDs)

	if cond.DifficultyMax < 5 {
		query = query.Where("difficulty <= ?", cond.DifficultyMax)
	}

	var recipes []models.Recipe
	if err := query.Limit(limit * 2).Find(&recipes).Error; err != nil {
		return nil, err
	}

	// 填充标签
	if err := s.fillTags(recipes); err != nil {
		return nil, err
	}

	// 排除不想要的口味
	if len(cond.ExcludedFlavors) > 0 {
		recipes = filterExcludedFlavors(recipes, cond.ExcludedFlavors)
	}

	// 随机打乱并取 limit 个
	rand.Shuffle(len(recipes), func(i, j int) {
		recipes[i], recipes[j] = recipes[j], recipes[i]
	})

	if len(recipes) > limit {
		recipes = recipes[:limit]
	}

	return recipes, nil
}

// fillTags 填充菜谱标签
func (s *RecommendService) fillTags(recipes []models.Recipe) error {
	if len(recipes) == 0 {
		return nil
	}

	recipeIDs := make([]string, len(recipes))
	for i, r := range recipes {
		recipeIDs[i] = r.RecipeID
	}

	var tags []models.Tag
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&tags).Error; err != nil {
		return err
	}

	recipeTagsMap := make(map[string][]models.Tag)
	for _, t := range tags {
		recipeTagsMap[t.RecipeID] = append(recipeTagsMap[t.RecipeID], t)
	}

	for i := range recipes {
		recipes[i].Tags = recipeTagsMap[recipes[i].RecipeID]
	}

	return nil
}

// generateReason 生成推荐理由
func (s *RecommendService) generateReason(result *RecommendResult) string {
	var reason string

	// 天气描述
	if result.Weather != nil {
		reason += fmt.Sprintf("现在%s", result.Weather.Weather)
		if result.Weather.Temperature != 0 {
			reason += fmt.Sprintf("，气温%.0f°C", result.Weather.Temperature)
		}
		reason += "，"
	}

	// 时段描述
	mealTimeNames := map[string]string{
		"breakfast": "早餐",
		"lunch":     "午餐",
		"afternoon": "下午茶",
		"dinner":    "晚餐",
		"midnight":  "夜宵",
	}
	if name, ok := mealTimeNames[result.MealTime]; ok {
		reason += fmt.Sprintf("正好是%s时间", name)
	}

	// 温度感受
	tempDesc := map[string]string{
		"cold": "，天气寒冷，推荐暖身滋补的菜品",
		"cool": "，天气凉爽，推荐温和可口的菜品",
		"warm": "，天气温暖，推荐清新爽口的菜品",
		"hot":  "，天气炎热，推荐清淡解暑的菜品",
	}
	if desc, ok := tempDesc[result.Temperature]; ok {
		reason += desc
	}

	return reason
}

// filterExcludedFlavors 过滤排除的口味
func filterExcludedFlavors(recipes []models.Recipe, excluded []string) []models.Recipe {
	excludeSet := make(map[string]bool)
	for _, f := range excluded {
		excludeSet[f] = true
	}

	var result []models.Recipe
	for _, r := range recipes {
		hasExcluded := false
		for _, t := range r.Tags {
			if t.Type == models.TagTypeFlavor && excludeSet[t.Value] {
				hasExcluded = true
				break
			}
		}
		if !hasExcluded {
			result = append(result, r)
		}
	}
	return result
}

// contains 检查字符串是否包含子串
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
