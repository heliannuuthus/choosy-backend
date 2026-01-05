package recommend

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"choosy-backend/internal/amap"
	"choosy-backend/internal/config"
	"choosy-backend/internal/logger"
	"choosy-backend/internal/models"
	"choosy-backend/internal/utils"

	"github.com/invopop/jsonschema"
	"github.com/sashabaranov/go-openai"
	"gorm.io/gorm"
)

// Service 推荐服务
type Service struct {
	db        *gorm.DB
	amap      *amap.Client
	llmClient *openai.Client
}

// WeatherInfo 天气信息
type WeatherInfo struct {
	Temperature float64 `json:"temperature"`
	Humidity    int     `json:"humidity"`
	Weather     string  `json:"weather"`
	City        string  `json:"city"`
}

// Context 推荐上下文
type Context struct {
	UserID    string  `json:"user_id,omitempty"` // 新增：用户 ID
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

// UserHistory 用户历史
type UserHistory struct {
	FavoriteRecipes []RecipeInfo `json:"favorite_recipes"`
	ViewedRecipes   []RecipeInfo `json:"viewed_recipes"`
	RecentDislikes  []string     `json:"recent_dislikes"`
}

// RecipeInfo 菜谱基本信息
type RecipeInfo struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags"`
	Description string   `json:"description,omitempty"`
}

// LLMRecommendation LLM 推荐结果
type LLMRecommendation struct {
	RecipeIDs []string `json:"recipe_ids" jsonschema:"description=推荐的菜谱ID列表,minItems=1"` // 推荐的菜谱 ID
	Reason    string   `json:"reason" jsonschema:"description=详细的推荐理由,100-150字"`         // 推荐理由
}

// JSONSchema 实现 json.Marshaler，用于结构化输出
type JSONSchema struct {
	schema interface{}
}

func (j JSONSchema) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.schema)
}

// generateSchema 生成 JSON Schema
func generateSchema[T any]() interface{} {
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:            true,
	}
	var v T
	schema := reflector.Reflect(v)
	return schema
}

// recommendationSchema 推荐结果的 JSON Schema
var recommendationSchema = generateSchema[LLMRecommendation]()

// NewService 创建推荐服务
func NewService(db *gorm.DB) *Service {
	// 配置 OpenRouter 客户端
	apiKey := config.GetString("openrouter.api_key")
	clientConfig := openai.DefaultConfig(apiKey)
	clientConfig.BaseURL = "https://openrouter.ai/api/v1"

	return &Service{
		db:        db,
		amap:      amap.GetClient(),
		llmClient: openai.NewClientWithConfig(clientConfig),
	}
}

// GetRecommendations 获取推荐菜谱（基于 LLM）
func (s *Service) GetRecommendations(ctx *Context, limit int) (*Result, error) {
	result := &Result{}

	// 1. 获取天气信息
	weather, err := s.amap.GetWeather(ctx.Latitude, ctx.Longitude)
	if err != nil {
		logger.Warnf("获取天气失败，使用默认值: %v", err)
		weather = &amap.Weather{Temperature: 20, Weather: "晴"}
	}
	result.Weather = &WeatherInfo{
		Temperature: weather.Temperature,
		Humidity:    weather.Humidity,
		Weather:     weather.Weather,
	}

	// 2. 提取上下文特征
	t := time.UnixMilli(ctx.Timestamp)
	result.MealTime = utils.GetMealTime(t)
	result.Season = utils.GetSeason(t)
	result.Temperature = getTemperatureFeeling(weather.Temperature)

	// 3. 获取用户历史（如果有用户 ID）
	var userHistory *UserHistory
	if ctx.UserID != "" {
		userHistory, err = s.getUserHistory(ctx.UserID)
		if err != nil {
			logger.Warnf("获取用户历史失败: %v", err)
		}
	}

	// 4. 使用 LLM 生成推荐
	llmResult, err := s.getLLMRecommendations(result, userHistory, limit)
	if err != nil {
		logger.Errorf("[Recommend] LLM 推荐失败: %v, 错误详情: %+v", err, err)
		return nil, fmt.Errorf("LLM 推荐失败: %w", err)
	}

	// 5. 查询推荐的菜谱
	recipes, err := s.queryRecipesByIDs(llmResult.RecipeIDs)
	if err != nil {
		logger.Errorf("查询菜谱失败: %v", err)
		return s.getFallbackRecommendations(result, limit)
	}

	// 6. 填充标签信息
	if err := s.fillTags(recipes); err != nil {
		logger.Warnf("填充标签失败: %v", err)
	}

	result.Recipes = recipes
	result.Reason = llmResult.Reason

	logger.Infof("[Recommend] LLM 推荐成功 - UserID: %s, 推荐数量: %d", ctx.UserID, len(recipes))

	return result, nil
}

// getUserHistory 获取用户历史
func (s *Service) getUserHistory(userID string) (*UserHistory, error) {
	history := &UserHistory{
		FavoriteRecipes: []RecipeInfo{},
		ViewedRecipes:   []RecipeInfo{},
		RecentDislikes:  []string{},
	}

	// 获取收藏的菜谱（最近30个）
	var favorites []models.Favorite
	err := s.db.Where("openid = ?", userID).
		Order("created_at DESC").
		Limit(30).
		Find(&favorites).Error
	if err != nil {
		return nil, err
	}

	if len(favorites) > 0 {
		favoriteIDs := make([]string, len(favorites))
		for i, f := range favorites {
			favoriteIDs[i] = f.RecipeID
		}

		var recipes []models.Recipe
		s.db.Where("recipe_id IN ?", favoriteIDs).Find(&recipes)

		// 填充标签
		_ = s.fillTags(recipes)

		for _, r := range recipes {
			tags := make([]string, len(r.Tags))
			for i, t := range r.Tags {
				tags[i] = t.Value
			}
			desc := ""
			if r.Description != nil {
				desc = *r.Description
			}
			history.FavoriteRecipes = append(history.FavoriteRecipes, RecipeInfo{
				Name:        r.Name,
				Category:    r.Category,
				Tags:        tags,
				Description: desc,
			})
		}
	}

	// TODO: 如果有浏览历史表，也可以添加
	// TODO: 如果有"不感兴趣"功能，也可以添加

	return history, nil
}

// getLLMRecommendations 使用 LLM 生成推荐
func (s *Service) getLLMRecommendations(result *Result, userHistory *UserHistory, limit int) (*LLMRecommendation, error) {
	// 1. 获取候选菜谱池
	// 如果模型不支持 tool use，需要包含更多信息
	var allRecipes []models.Recipe
	err := s.db.Select("recipe_id, name, category, description, difficulty, total_time_minutes").
		Limit(500).
		Find(&allRecipes).Error
	if err != nil {
		return nil, err
	}

	// 填充标签
	_ = s.fillTags(allRecipes)

	// 2. 构建候选菜谱列表
	type CandidateRecipe struct {
		ID               string   `json:"id"`
		Name             string   `json:"name"`
		Category         string   `json:"category"`
		Tags             []string `json:"tags"`
		Description      string   `json:"description"`
		Difficulty       int      `json:"difficulty"`
		TotalTimeMinutes *int     `json:"total_time_minutes,omitempty"`
	}

	candidates := make([]CandidateRecipe, len(allRecipes))
	for i, r := range allRecipes {
		tags := make([]string, len(r.Tags))
		for j, t := range r.Tags {
			tags[j] = t.Value
		}
		desc := ""
		if r.Description != nil {
			desc = *r.Description
		}
		candidates[i] = CandidateRecipe{
			ID:               r.RecipeID,
			Name:             r.Name,
			Category:         r.Category,
			Tags:             tags,
			Description:      desc,
			Difficulty:       r.Difficulty,
			TotalTimeMinutes: r.TotalTimeMinutes,
		}
	}

	candidatesJSON, _ := json.MarshalIndent(candidates, "", "  ")

	// 3. 构建 Prompt
	prompt := s.buildRecommendPrompt(result, userHistory, string(candidatesJSON), limit)

	// 4. 定义查询菜品详情的工具（可选，某些模型不支持）
	tools := []openai.Tool{
		{
			Type: openai.ToolTypeFunction,
			Function: &openai.FunctionDefinition{
				Name:        "get_recipe_details",
				Description: "查询菜品的详细信息，包括分类、标签、描述、难度、制作时间等。当需要了解菜品的具体信息以做出更好的推荐时，可以调用此工具。",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"recipe_ids": map[string]interface{}{
							"type":        "array",
							"description": "要查询的菜品 ID 列表",
							"items": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"required": []string{"recipe_ids"},
				},
			},
		},
	}

	// 5. 调用 LLM（支持多轮对话和 function calling）
	logger.Infof("[Recommend] 调用 LLM - Prompt 长度: %d", len(prompt))

	model := config.GetString("openrouter.model")
	if model == "" {
		model = "meta-llama/llama-3.1-405b-instruct:free"
		logger.Warnf("[Recommend] 未配置 openrouter.model，使用默认模型: %s", model)
	}

	messages := []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleSystem,
			Content: "你是一个专业的美食推荐助手。请根据用户喜好、当前场景和候选菜谱，推荐最适合的菜品。推荐理由需要详细、具体、有说服力。如果需要了解菜品的详细信息，可以使用 get_recipe_details 工具查询。",
		},
		{
			Role:    openai.ChatMessageRoleUser,
			Content: prompt,
		},
	}

	maxIterations := 5
	for i := 0; i < maxIterations; i++ {
		req := openai.ChatCompletionRequest{
			Model:       model,
			Messages:    messages,
			Tools:       tools,
			Temperature: 0.9,
			ResponseFormat: &openai.ChatCompletionResponseFormat{
				Type: openai.ChatCompletionResponseFormatTypeJSONObject,
				JSONSchema: &openai.ChatCompletionResponseFormatJSONSchema{
					Name:        "recommendation",
					Description: "美食推荐结果",
					Schema:      JSONSchema{schema: recommendationSchema},
					Strict:      true,
				},
			},
		}

		logger.Infof("[Recommend] LLM 请求（第 %d 轮）- Model: %s, Messages: %d",
			i+1, req.Model, len(req.Messages))

		resp, err := s.llmClient.CreateChatCompletion(context.Background(), req)
		if err != nil {
			if apiErr, ok := err.(*openai.APIError); ok {
				logger.Errorf("[Recommend] LLM 调用失败 - Model: %s, APIError详情: Code=%d, HTTPStatusCode=%d, Message=%s",
					model, apiErr.Code, apiErr.HTTPStatusCode, apiErr.Message)
				return nil, fmt.Errorf("LLM 调用失败 (model: %s): status code: %d, message: %s",
					model, apiErr.Code, apiErr.Message)
			}
			logger.Errorf("[Recommend] LLM 调用失败 - Model: %s, 错误类型: %T, 错误信息: %v", model, err, err)
			return nil, fmt.Errorf("LLM 调用失败 (model: %s): %w", model, err)
		}

		if len(resp.Choices) == 0 {
			return nil, fmt.Errorf("LLM 未返回结果 (model: %s)", model)
		}

		choice := resp.Choices[0]
		messages = append(messages, choice.Message)

		// 检查是否有 function call
		if len(choice.Message.ToolCalls) > 0 {
			logger.Infof("[Recommend] LLM 请求查询菜品详情，调用次数: %d", len(choice.Message.ToolCalls))
			// 处理 function calls
			for _, toolCall := range choice.Message.ToolCalls {
				if toolCall.Function.Name == "get_recipe_details" {
					var args map[string]interface{}
					if err := json.Unmarshal([]byte(toolCall.Function.Arguments), &args); err != nil {
						logger.Errorf("[Recommend] 解析 function call 参数失败: %v", err)
						continue
					}

					recipeIDs, ok := args["recipe_ids"].([]interface{})
					if !ok {
						logger.Errorf("[Recommend] recipe_ids 参数格式错误")
						continue
					}

					ids := make([]string, len(recipeIDs))
					for j, id := range recipeIDs {
						ids[j] = id.(string)
					}

					details := s.getRecipeDetails(ids)
					detailsJSON, _ := json.MarshalIndent(details, "", "  ")

					messages = append(messages, openai.ChatCompletionMessage{
						Role:       openai.ChatMessageRoleTool,
						Content:    string(detailsJSON),
						ToolCallID: toolCall.ID,
					})
				}
			}
			continue
		}

		// 没有 function call，解析最终结果
		content := choice.Message.Content
		logger.Infof("[Recommend] LLM 最终响应: %s", content)

		// 使用结构化输出后，响应应该是有效的 JSON，但仍需要清理可能的 markdown 代码块
		content = strings.TrimSpace(content)
		if strings.HasPrefix(content, "```json") {
			content = strings.TrimPrefix(content, "```json")
			content = strings.TrimPrefix(content, "```")
			if idx := strings.LastIndex(content, "```"); idx != -1 {
				content = content[:idx]
			}
			content = strings.TrimSpace(content)
		} else if strings.HasPrefix(content, "```") {
			content = strings.TrimPrefix(content, "```")
			if idx := strings.LastIndex(content, "```"); idx != -1 {
				content = content[:idx]
			}
			content = strings.TrimSpace(content)
		}

		var llmResult LLMRecommendation
		if err := json.Unmarshal([]byte(content), &llmResult); err != nil {
			return nil, fmt.Errorf("解析 LLM 响应失败: %w, 响应内容: %s", err, content)
		}

		return &llmResult, nil
	}

	return nil, fmt.Errorf("LLM 调用超过最大迭代次数")
}

// buildRecommendPrompt 构建推荐 Prompt
func (s *Service) buildRecommendPrompt(result *Result, userHistory *UserHistory, candidatesJSON string, limit int) string {
	prompt := fmt.Sprintf(`请根据以下信息推荐 %d 道菜：

## 当前场景
- 天气：%s，温度 %.0f°C
- 用餐时间：%s
- 季节：%s

`, limit, result.Weather.Weather, result.Weather.Temperature, getMealTimeChinese(result.MealTime), getSeasonChinese(result.Season))

	// 添加用户历史
	if userHistory != nil && len(userHistory.FavoriteRecipes) > 0 {
		prompt += "## 用户喜好（基于收藏历史）\n"
		prompt += "以下是用户最近收藏的菜品，请分析其偏好模式（如菜系、口味、场景等）：\n"
		for i, r := range userHistory.FavoriteRecipes {
			if i >= 10 { // 最多展示 10 个
				break
			}
			tagsStr := joinStrings(r.Tags, "、")
			if tagsStr == "" {
				tagsStr = "无标签"
			}
			prompt += fmt.Sprintf("- %s（%s）标签：%s\n", r.Name, r.Category, tagsStr)
		}
		prompt += "\n"
	}

	prompt += fmt.Sprintf(`## 候选菜谱
以下是候选菜谱的详细信息，包括 ID、名称、分类、标签、描述、难度、制作时间等。

%s

## 要求
1. 从候选菜谱中选择 %d 道最适合的菜品
2. 综合考虑当前场景、用户喜好（如有）、菜品特点等因素
3. 生成详细的推荐理由（100-150字），说明推荐这些菜品的原因

请按照指定的 JSON Schema 格式返回结果。`, candidatesJSON, limit)

	return prompt
}

// getRecipeDetails 查询菜品详细信息（用于 function calling）
func (s *Service) getRecipeDetails(ids []string) []map[string]interface{} {
	if len(ids) == 0 {
		return []map[string]interface{}{}
	}

	var recipes []models.Recipe
	err := s.db.Select("recipe_id, name, category, description, difficulty, total_time_minutes, prep_time_minutes, cook_time_minutes").
		Where("recipe_id IN ?", ids).
		Find(&recipes).Error
	if err != nil {
		logger.Errorf("[Recommend] 查询菜品详情失败: %v", err)
		return []map[string]interface{}{}
	}

	_ = s.fillTags(recipes)

	details := make([]map[string]interface{}, len(recipes))
	for i, r := range recipes {
		tags := make([]string, len(r.Tags))
		for j, t := range r.Tags {
			tags[j] = t.Value
		}
		desc := ""
		if r.Description != nil {
			desc = *r.Description
		}

		detail := map[string]interface{}{
			"id":          r.RecipeID,
			"name":        r.Name,
			"category":    r.Category,
			"tags":        tags,
			"description": desc,
			"difficulty":  r.Difficulty,
		}

		if r.TotalTimeMinutes != nil {
			detail["total_time_minutes"] = *r.TotalTimeMinutes
		}
		if r.PrepTimeMinutes != nil {
			detail["prep_time_minutes"] = *r.PrepTimeMinutes
		}
		if r.CookTimeMinutes != nil {
			detail["cook_time_minutes"] = *r.CookTimeMinutes
		}

		details[i] = detail
	}

	return details
}

// queryRecipesByIDs 根据 ID 查询菜谱
func (s *Service) queryRecipesByIDs(ids []string) ([]models.Recipe, error) {
	if len(ids) == 0 {
		return []models.Recipe{}, nil
	}

	var recipes []models.Recipe
	err := s.db.Where("recipe_id IN ?", ids).Find(&recipes).Error
	return recipes, err
}

// fillTags 填充菜谱的标签信息
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

// getFallbackRecommendations 降级方案：返回随机菜谱
func (s *Service) getFallbackRecommendations(result *Result, limit int) (*Result, error) {
	var recipes []models.Recipe
	err := s.db.Order("RANDOM()").Limit(limit).Find(&recipes).Error
	if err != nil {
		return nil, err
	}

	_ = s.fillTags(recipes)

	result.Recipes = recipes
	result.Reason = "为您推荐一些美味菜品"

	return result, nil
}

// 辅助函数
func getTemperatureFeeling(temp float64) string {
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

func getMealTimeChinese(mealTime string) string {
	names := map[string]string{
		"breakfast": "早餐",
		"lunch":     "午餐",
		"afternoon": "下午茶",
		"dinner":    "晚餐",
		"night":     "夜宵",
	}
	if name, ok := names[mealTime]; ok {
		return name
	}
	return "用餐"
}

func getSeasonChinese(season string) string {
	names := map[string]string{
		"spring": "春季",
		"summer": "夏季",
		"autumn": "秋季",
		"winter": "冬季",
	}
	if name, ok := names[season]; ok {
		return name
	}
	return season
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
