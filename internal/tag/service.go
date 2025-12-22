package tag

import (
	"choosy-backend/internal/models"

	"gorm.io/gorm"
)

// Service 标签服务
type Service struct {
	db *gorm.DB
}

// NewService 创建标签服务
func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// GetTagsByRecipe 获取菜谱的所有标签
func (s *Service) GetTagsByRecipe(recipeID string) ([]models.Tag, error) {
	var tags []models.Tag
	err := s.db.Where("recipe_id = ?", recipeID).Order("type, _id").Find(&tags).Error
	return tags, err
}

// GetTagsByRecipeAndType 按类型获取某菜谱的标签
func (s *Service) GetTagsByRecipeAndType(recipeID string, tagType models.TagType) ([]models.Tag, error) {
	var tags []models.Tag
	err := s.db.Where("recipe_id = ? AND type = ?", recipeID, tagType).Find(&tags).Error
	return tags, err
}

// AddTag 添加标签
func (s *Service) AddTag(recipeID string, value string, label string, tagType models.TagType) error {
	tag := models.Tag{
		RecipeID: recipeID,
		Value:    value,
		Label:    label,
		Type:     tagType,
	}
	return s.db.Create(&tag).Error
}

// DeleteRecipeTags 删除菜谱的所有标签
func (s *Service) DeleteRecipeTags(recipeID string) error {
	return s.db.Where("recipe_id = ?", recipeID).Delete(&models.Tag{}).Error
}

// DeleteRecipeTagsByType 删除菜谱某类型的标签
func (s *Service) DeleteRecipeTagsByType(recipeID string, tagType models.TagType) error {
	return s.db.Where("recipe_id = ? AND type = ?", recipeID, tagType).Delete(&models.Tag{}).Error
}

// GetRecipesByTagValue 获取包含某标签的所有菜谱 ID
func (s *Service) GetRecipesByTagValue(value string) ([]string, error) {
	var recipeIDs []string
	err := s.db.Model(&models.Tag{}).
		Where("value = ?", value).
		Distinct("recipe_id").
		Pluck("recipe_id", &recipeIDs).Error
	return recipeIDs, err
}

// GetRecipesByTagType 获取包含某类型标签的所有菜谱 ID
func (s *Service) GetRecipesByTagType(tagType models.TagType) ([]string, error) {
	var recipeIDs []string
	err := s.db.Model(&models.Tag{}).
		Where("type = ?", tagType).
		Distinct("recipe_id").
		Pluck("recipe_id", &recipeIDs).Error
	return recipeIDs, err
}

// TagValue 标签值
type TagValue struct {
	Value string
	Label string
}

// GetDistinctTagValues 获取所有去重的标签值
func (s *Service) GetDistinctTagValues(tagType models.TagType) ([]TagValue, error) {
	var results []TagValue
	err := s.db.Model(&models.Tag{}).
		Select("DISTINCT value, label").
		Where("type = ?", tagType).
		Order("value").
		Scan(&results).Error
	return results, err
}

