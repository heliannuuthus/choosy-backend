package tag

import (
	"errors"
	"fmt"

	"zwei-backend/internal/models"

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

// TagValue 标签值
type TagValue struct {
	Value string
	Label string
}

// ==================== 标签定义相关（t_tag 表）====================

// GetTagByValue 根据 value 和 type 获取标签定义（懒加载：查询一条缓存一条）
func (s *Service) GetTagByValue(value string, tagType models.TagType) (*models.Tag, error) {
	cache := getTagCache()
	return cache.Get(tagType, value, s.db)
}

// GetTagsByType 根据类型获取所有标签定义（懒加载）
func (s *Service) GetTagsByType(tagType models.TagType) ([]models.Tag, error) {
	cache := getTagCache()
	tagPtrs, err := cache.GetByType(tagType, s.db)
	if err != nil {
		return nil, err
	}
	if tagPtrs == nil {
		return []models.Tag{}, nil
	}

	tags := make([]models.Tag, len(tagPtrs))
	for i, tagPtr := range tagPtrs {
		tags[i] = *tagPtr
	}
	return tags, nil
}

// GetAllTags 获取所有标签定义（按类型分组，懒加载）
func (s *Service) GetAllTags() (map[models.TagType][]models.Tag, error) {
	cache := getTagCache()
	tagPtrsMap, err := cache.GetAll(s.db)
	if err != nil {
		return nil, err
	}

	result := make(map[models.TagType][]models.Tag)
	for tagType, tagPtrs := range tagPtrsMap {
		tags := make([]models.Tag, len(tagPtrs))
		for i, tagPtr := range tagPtrs {
			tags[i] = *tagPtr
		}
		result[tagType] = tags
	}
	return result, nil
}

// CreateTag 创建标签定义（如果不存在）
func (s *Service) CreateTag(value string, label string, tagType models.TagType) (*models.Tag, error) {
	cache := getTagCache()

	// 先检查缓存（懒加载）
	if tag, err := cache.Get(tagType, value, s.db); err == nil {
		return tag, nil // 已存在，直接返回
	}

	// 检查数据库
	var existing models.Tag
	err := s.db.Where("type = ? AND value = ?", tagType, value).First(&existing).Error
	if err == nil {
		// 已存在，设置缓存
		cache.Set(&existing)
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// 创建新标签
	tag := models.Tag{
		Value: value,
		Label: label,
		Type:  tagType,
	}
	if err := s.db.Create(&tag).Error; err != nil {
		return nil, err
	}

	// 设置缓存
	cache.Set(&tag)
	return &tag, nil
}

// UpdateTag 更新标签定义（延迟双删策略）
func (s *Service) UpdateTag(value string, label string, tagType models.TagType) error {
	cache := getTagCache()

	// 延迟双删策略：第一次删除缓存
	cache.Delete(tagType, value)

	// 更新数据库
	var tag models.Tag
	if err := s.db.Where("type = ? AND value = ?", tagType, value).First(&tag).Error; err != nil {
		return fmt.Errorf("标签不存在: %s", value)
	}

	result := s.db.Model(&tag).Update("label", label)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("标签不存在: %s", value)
	}

	// 延迟双删策略：延迟后再次删除缓存（保证最终一致性）
	cache.DeleteWithDelay(tagType, value, tagDeleteDelay)

	return nil
}

// DeleteTag 删除标签定义（延迟双删策略）
func (s *Service) DeleteTag(value string, tagType models.TagType) error {
	cache := getTagCache()

	// 延迟双删策略：第一次删除缓存
	cache.Delete(tagType, value)

	// 检查是否有菜谱关联
	var count int64
	s.db.Model(&models.RecipeTag{}).
		Where("tag_value = ? AND tag_type = ?", value, tagType).
		Count(&count)
	if count > 0 {
		return fmt.Errorf("标签已被 %d 个菜谱使用，无法删除", count)
	}

	// 删除数据库记录
	result := s.db.Where("type = ? AND value = ?", tagType, value).
		Delete(&models.Tag{})

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("标签不存在: %s", value)
	}

	// 延迟双删策略：延迟后再次删除缓存（保证最终一致性）
	cache.DeleteWithDelay(tagType, value, tagDeleteDelay)

	return nil
}

// ==================== 菜谱标签关联相关（t_recipe_tag 表）====================

// GetTagsByRecipe 获取菜谱的所有标签（内存组装）
func (s *Service) GetTagsByRecipe(recipeID string) ([]models.Tag, error) {
	// 1. 查询关联表
	var recipeTags []models.RecipeTag
	if err := s.db.Where("recipe_id = ?", recipeID).Find(&recipeTags).Error; err != nil {
		return nil, err
	}

	if len(recipeTags) == 0 {
		return []models.Tag{}, nil
	}

	// 2. 提取所有 tag_value 和 tag_type
	tagMap := make(map[string]models.TagType) // value -> type
	for _, rt := range recipeTags {
		tagMap[rt.TagValue] = rt.TagType
	}

	// 3. 从缓存获取标签定义（懒加载）
	cache := getTagCache()
	result := make([]models.Tag, 0, len(recipeTags))
	for _, rt := range recipeTags {
		if tag, err := cache.Get(rt.TagType, rt.TagValue, s.db); err == nil {
			result = append(result, *tag)
		}
	}

	return result, nil
}

// GetTagsByRecipeAndType 按类型获取某菜谱的标签（内存组装）
func (s *Service) GetTagsByRecipeAndType(recipeID string, tagType models.TagType) ([]models.Tag, error) {
	// 1. 查询关联表
	var recipeTags []models.RecipeTag
	if err := s.db.Where("recipe_id = ? AND tag_type = ?", recipeID, tagType).Find(&recipeTags).Error; err != nil {
		return nil, err
	}

	if len(recipeTags) == 0 {
		return []models.Tag{}, nil
	}

	// 2. 从缓存获取标签定义（懒加载）
	cache := getTagCache()
	result := make([]models.Tag, 0, len(recipeTags))
	for _, rt := range recipeTags {
		if tag, err := cache.Get(rt.TagType, rt.TagValue, s.db); err == nil {
			result = append(result, *tag)
		}
	}

	return result, nil
}

// AddTagToRecipe 为菜谱添加标签（内存组装）
func (s *Service) AddTagToRecipe(recipeID string, tagValue string, tagType models.TagType) error {
	// 1. 确保标签定义存在
	_, err := s.GetTagByValue(tagValue, tagType)
	if err != nil {
		return fmt.Errorf("标签不存在: %s (type: %s)", tagValue, tagType)
	}

	// 2. 检查关联是否已存在
	var existing models.RecipeTag
	err = s.db.Where("recipe_id = ? AND tag_value = ? AND tag_type = ?", recipeID, tagValue, tagType).
		First(&existing).Error
	if err == nil {
		return nil // 已存在，直接返回
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	// 3. 创建关联
	recipeTag := models.RecipeTag{
		RecipeID: recipeID,
		TagValue: tagValue,
		TagType:  tagType,
	}
	return s.db.Create(&recipeTag).Error
}

// RemoveTagFromRecipe 移除菜谱的标签
func (s *Service) RemoveTagFromRecipe(recipeID string, tagValue string, tagType models.TagType) error {
	result := s.db.Where("recipe_id = ? AND tag_value = ? AND tag_type = ?", recipeID, tagValue, tagType).
		Delete(&models.RecipeTag{})

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("关联不存在")
	}
	return nil
}

// DeleteRecipeTags 删除菜谱的所有标签
func (s *Service) DeleteRecipeTags(recipeID string) error {
	return s.db.Where("recipe_id = ?", recipeID).Delete(&models.RecipeTag{}).Error
}

// DeleteRecipeTagsByType 删除菜谱某类型的标签
func (s *Service) DeleteRecipeTagsByType(recipeID string, tagType models.TagType) error {
	return s.db.Where("recipe_id = ? AND tag_type = ?", recipeID, tagType).
		Delete(&models.RecipeTag{}).Error
}

// GetRecipesByTagValue 获取包含某标签的所有菜谱 ID（内存组装）
func (s *Service) GetRecipesByTagValue(value string) ([]string, error) {
	var recipeIDs []string
	err := s.db.Model(&models.RecipeTag{}).
		Where("tag_value = ?", value).
		Distinct("recipe_id").
		Pluck("recipe_id", &recipeIDs).Error
	return recipeIDs, err
}

// GetRecipesByTagType 获取包含某类型标签的所有菜谱 ID（内存组装）
func (s *Service) GetRecipesByTagType(tagType models.TagType) ([]string, error) {
	var recipeIDs []string
	err := s.db.Model(&models.RecipeTag{}).
		Where("tag_type = ?", tagType).
		Distinct("recipe_id").
		Pluck("recipe_id", &recipeIDs).Error
	return recipeIDs, err
}

// ==================== 对外接口（兼容现有代码）====================

// GetDistinctTagValues 获取所有去重的标签值
// 选项类型（taboo/allergy）只返回选项；标签类型返回所有标签
func (s *Service) GetDistinctTagValues(tagType models.TagType) ([]TagValue, error) {
	tags, err := s.GetTagsByType(tagType)
	if err != nil {
		return nil, err
	}

	results := make([]TagValue, len(tags))
	for i, tag := range tags {
		results[i] = TagValue{Value: tag.Value, Label: tag.Label}
	}
	return results, nil
}

// GetOptions 获取选项列表（用于用户偏好设置）
func (s *Service) GetOptions(tagType models.TagType) ([]TagValue, error) {
	// 选项类型只返回选项
	if tagType != models.TagTypeTaboo && tagType != models.TagTypeAllergy {
		return nil, fmt.Errorf("无效的选项类型: %s", tagType)
	}

	return s.GetDistinctTagValues(tagType)
}

// GetTagsByRecipe 获取菜谱的所有标签（返回 TagValue，兼容旧接口）
func (s *Service) GetTagsByRecipeAsTagValue(recipeID string) ([]TagValue, error) {
	tags, err := s.GetTagsByRecipe(recipeID)
	if err != nil {
		return nil, err
	}

	results := make([]TagValue, len(tags))
	for i, tag := range tags {
		results[i] = TagValue{Value: tag.Value, Label: tag.Label}
	}
	return results, nil
}

// GetTagsByRecipeAndType 按类型获取某菜谱的标签（返回 TagValue，兼容旧接口）
func (s *Service) GetTagsByRecipeAndTypeAsTagValue(recipeID string, tagType models.TagType) ([]TagValue, error) {
	tags, err := s.GetTagsByRecipeAndType(recipeID, tagType)
	if err != nil {
		return nil, err
	}

	results := make([]TagValue, len(tags))
	for i, tag := range tags {
		results[i] = TagValue{Value: tag.Value, Label: tag.Label}
	}
	return results, nil
}

// AddTag 添加标签（兼容旧接口）
// 如果 recipeID 为空，只创建标签定义；如果不为空，创建标签定义并关联到菜谱
func (s *Service) AddTag(recipeID string, value string, label string, tagType models.TagType) error {
	// 1. 确保标签定义存在
	_, err := s.CreateTag(value, label, tagType)
	if err != nil {
		return err
	}

	// 2. 如果提供了 recipeID，创建关联
	if recipeID != "" {
		return s.AddTagToRecipe(recipeID, value, tagType)
	}

	return nil
}

// AddOption 添加选项（后台管理用）
func (s *Service) AddOption(value string, label string, tagType models.TagType) error {
	// 选项类型验证
	if tagType != models.TagTypeTaboo && tagType != models.TagTypeAllergy {
		return fmt.Errorf("无效的选项类型: %s", tagType)
	}

	_, err := s.CreateTag(value, label, tagType)
	return err
}

// UpdateOption 更新选项
func (s *Service) UpdateOption(value string, label string, tagType models.TagType) error {
	// 选项类型验证
	if tagType != models.TagTypeTaboo && tagType != models.TagTypeAllergy {
		return fmt.Errorf("无效的选项类型: %s", tagType)
	}

	return s.UpdateTag(value, label, tagType)
}

// DeleteOption 删除选项（需要检查是否有用户使用）
func (s *Service) DeleteOption(value string, tagType models.TagType) error {
	// 选项类型验证
	if tagType != models.TagTypeTaboo && tagType != models.TagTypeAllergy {
		return fmt.Errorf("无效的选项类型: %s", tagType)
	}

	// TODO: 检查用户偏好表中是否有用户使用此选项
	return s.DeleteTag(value, tagType)
}
