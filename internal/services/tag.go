package services

import (
	"choosy-backend/internal/models"

	"gorm.io/gorm"
)

// TagService 标签服务
type TagService struct {
	db *gorm.DB
}

// NewTagService 创建标签服务
func NewTagService(db *gorm.DB) *TagService {
	return &TagService{db: db}
}

// GetTagsByRecipe 获取菜谱的所有标签
func (s *TagService) GetTagsByRecipe(recipeID string) ([]models.Tag, error) {
	var tags []models.Tag
	err := s.db.Where("recipe_id = ?", recipeID).Order("type, _id").Find(&tags).Error
	return tags, err
}

// GetTagsByType 按类型获取某菜谱的标签
func (s *TagService) GetTagsByRecipeAndType(recipeID string, tagType models.TagType) ([]models.Tag, error) {
	var tags []models.Tag
	err := s.db.Where("recipe_id = ? AND type = ?", recipeID, tagType).Find(&tags).Error
	return tags, err
}

// AddTag 添加标签
func (s *TagService) AddTag(recipeID string, value string, label string, tagType models.TagType) error {
	tag := models.Tag{
		RecipeID: recipeID,
		Value:    value,
		Label:    label,
		Type:     tagType,
	}
	return s.db.Create(&tag).Error
}

// DeleteRecipeTags 删除菜谱的所有标签
func (s *TagService) DeleteRecipeTags(recipeID string) error {
	return s.db.Where("recipe_id = ?", recipeID).Delete(&models.Tag{}).Error
}

// DeleteRecipeTagsByType 删除菜谱某类型的标签
func (s *TagService) DeleteRecipeTagsByType(recipeID string, tagType models.TagType) error {
	return s.db.Where("recipe_id = ? AND type = ?", recipeID, tagType).Delete(&models.Tag{}).Error
}

// GetRecipesByTagValue 获取包含某标签的所有菜谱 ID
func (s *TagService) GetRecipesByTagValue(value string) ([]string, error) {
	var recipeIDs []string
	err := s.db.Model(&models.Tag{}).
		Where("value = ?", value).
		Distinct("recipe_id").
		Pluck("recipe_id", &recipeIDs).Error
	return recipeIDs, err
}

// GetRecipesByTagType 获取包含某类型标签的所有菜谱 ID
func (s *TagService) GetRecipesByTagType(tagType models.TagType) ([]string, error) {
	var recipeIDs []string
	err := s.db.Model(&models.Tag{}).
		Where("type = ?", tagType).
		Distinct("recipe_id").
		Pluck("recipe_id", &recipeIDs).Error
	return recipeIDs, err
}

// GetDistinctTagValues 获取所有去重的标签值
func (s *TagService) GetDistinctTagValues(tagType models.TagType) ([]struct {
	Value string
	Label string
}, error) {
	var results []struct {
		Value string
		Label string
	}
	err := s.db.Model(&models.Tag{}).
		Select("DISTINCT value, label").
		Where("type = ?", tagType).
		Order("value").
		Scan(&results).Error
	return results, err
}
