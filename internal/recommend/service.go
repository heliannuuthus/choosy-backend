package recommend

import (
	"fmt"
	"math/rand"
	"time"

	"choosy-backend/internal/amap"
	"choosy-backend/internal/models"
	"choosy-backend/internal/tag"
	"choosy-backend/internal/utils"

	"gorm.io/gorm"
)

// Service 推荐服务
type Service struct {
	db         *gorm.DB
	tagService *tag.Service
	amap       *amap.Client
}

// WeatherInfo 天气信息
type WeatherInfo struct {
	Temperature float64 `json:"temperature"`
	Humidity    int     `json:"humidity"`
	Weather     string  `json:"weather"`
	WeatherCode string  `json:"weather_code"`
	City        string  `json:"city"`
}

// Context 推荐上下文
type Context struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timestamp int64   `json:"timestamp"`
}

// Result 推荐结果
type Result struct {
	Recipes     []models.Recipe `json:"recipes"`
	Reason      string          `json:"reason"`
	Weather     *WeatherInfo    `json:"weather"`
	MealTime    string          `json:"meal_time"`
	Season      string          `json:"season"`
	Temperature string          `json:"temperature"`
}

// NewService 创建推荐服务
func NewService(db *gorm.DB) *Service {
	return &Service{
		db:         db,
		tagService: tag.NewService(db),
		amap:       amap.GetClient(),
	}
}

// GetRecommendations 获取推荐菜谱
func (s *Service) GetRecommendations(ctx *Context, limit int) (*Result, error) {
	result := &Result{}

	weather, err := s.amap.GetWeather(ctx.Latitude, ctx.Longitude)
	if err != nil {
		weather = &amap.Weather{Temperature: 20, Weather: "晴"}
	}
	result.Weather = &WeatherInfo{
		Temperature: weather.Temperature,
		Humidity:    weather.Humidity,
		Weather:     weather.Weather,
	}

	t := time.UnixMilli(ctx.Timestamp)
	result.MealTime = utils.GetMealTime(t)
	result.Season = utils.GetSeason(t)
	result.Temperature = s.getTemperatureFeeling(weather.Temperature)

	conditions := s.buildRecommendConditions(result)

	recipes, err := s.queryRecipes(conditions, limit)
	if err != nil {
		return nil, err
	}
	result.Recipes = recipes

	result.Reason = s.generateReason(result)

	return result, nil
}

func (s *Service) getTemperatureFeeling(temp float64) string {
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

type recommendConditions struct {
	PreferredFlavors []string
	PreferredScenes  []string
	ExcludedFlavors  []string
	DifficultyMax    int
}

func (s *Service) buildRecommendConditions(result *Result) *recommendConditions {
	cond := &recommendConditions{
		DifficultyMax: 5,
	}

	switch result.Temperature {
	case "cold":
		cond.PreferredFlavors = append(cond.PreferredFlavors, "warm", "nourishing", "savory")
		cond.PreferredScenes = append(cond.PreferredScenes, "winter", "home_cooking")
	case "cool":
		cond.PreferredFlavors = append(cond.PreferredFlavors, "savory", "mild")
	case "warm":
		cond.PreferredFlavors = append(cond.PreferredFlavors, "fresh", "light")
	case "hot":
		cond.PreferredFlavors = append(cond.PreferredFlavors, "light", "fresh", "sour", "cool")
		cond.PreferredScenes = append(cond.PreferredScenes, "summer", "light_meal")
		cond.ExcludedFlavors = append(cond.ExcludedFlavors, "heavy", "greasy")
	}

	switch result.MealTime {
	case "breakfast":
		cond.PreferredScenes = append(cond.PreferredScenes, "breakfast", "quick")
		cond.DifficultyMax = 3
	case "lunch":
		cond.PreferredScenes = append(cond.PreferredScenes, "lunch", "quick")
	case "afternoon":
		cond.PreferredScenes = append(cond.PreferredScenes, "snack", "light_meal")
	case "dinner":
		cond.PreferredScenes = append(cond.PreferredScenes, "dinner", "home_cooking")
	case "night":
		cond.PreferredScenes = append(cond.PreferredScenes, "midnight_snack", "quick")
		cond.DifficultyMax = 3
	}

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

func (s *Service) queryRecipes(cond *recommendConditions, limit int) ([]models.Recipe, error) {
	var preferredTags []string
	preferredTags = append(preferredTags, cond.PreferredFlavors...)
	preferredTags = append(preferredTags, cond.PreferredScenes...)

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
			Limit(limit * 3).
			Find(&recipeCounts).Error
		if err != nil {
			return nil, err
		}
	}

	var recipeIDs []string
	for _, rc := range recipeCounts {
		recipeIDs = append(recipeIDs, rc.RecipeID)
	}

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

	query := s.db.Model(&models.Recipe{}).
		Where("recipe_id IN ?", recipeIDs)

	if cond.DifficultyMax < 5 {
		query = query.Where("difficulty <= ?", cond.DifficultyMax)
	}

	var recipes []models.Recipe
	if err := query.Limit(limit * 2).Find(&recipes).Error; err != nil {
		return nil, err
	}

	if err := s.fillTags(recipes); err != nil {
		return nil, err
	}

	if len(cond.ExcludedFlavors) > 0 {
		recipes = filterExcludedFlavors(recipes, cond.ExcludedFlavors)
	}

	rand.Shuffle(len(recipes), func(i, j int) {
		recipes[i], recipes[j] = recipes[j], recipes[i]
	})

	if len(recipes) > limit {
		recipes = recipes[:limit]
	}

	return recipes, nil
}

func (s *Service) fillTags(recipes []models.Recipe) error {
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

func (s *Service) generateReason(result *Result) string {
	var reason string

	if result.Weather != nil {
		reason += fmt.Sprintf("现在%s", result.Weather.Weather)
		if result.Weather.Temperature != 0 {
			reason += fmt.Sprintf("，气温%.0f°C", result.Weather.Temperature)
		}
		reason += "，"
	}

	mealTimeNames := map[string]string{
		"breakfast": "早餐",
		"lunch":     "午餐",
		"afternoon": "下午茶",
		"dinner":    "晚餐",
		"night":     "夜宵",
	}
	if name, ok := mealTimeNames[result.MealTime]; ok {
		reason += fmt.Sprintf("正好是%s时间", name)
	}

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

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

