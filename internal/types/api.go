package types

import "zwei-backend/internal/models"

// RecipeListItem 菜谱列表项
type RecipeListItem struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Description      *string     `json:"description"`
	Category         string      `json:"category"`
	Difficulty       int         `json:"difficulty"`
	Tags             TagsGrouped `json:"tags"`
	ImagePath        *string     `json:"image_path"`
	TotalTimeMinutes *int        `json:"total_time_minutes"`
}

// TagsGrouped 标签分组
type TagsGrouped struct {
	Cuisines []string `json:"cuisines"`
	Flavors  []string `json:"flavors"`
	Scenes   []string `json:"scenes"`
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
