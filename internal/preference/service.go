package preference

import (
	"zwei-backend/internal/models"
	"zwei-backend/internal/tag"

	"sync"

	"gorm.io/gorm"
)

// Service 用户偏好服务
type Service struct {
	db         *gorm.DB
	tagService *tag.Service
}

// NewService 创建用户偏好服务
func NewService(db *gorm.DB) *Service {
	return &Service{
		db:         db,
		tagService: tag.NewService(db),
	}
}

// GetDB 获取数据库连接（供 handler 使用）
func (s *Service) GetDB() *gorm.DB {
	return s.db
}

// GetOptions 获取所有偏好选项（从缓存索引获取，性能最优）
func (s *Service) GetOptions() (*OptionsResponse, error) {
	var flavors, taboos, allergies []models.Tag
	var flavorsErr, taboosErr, allergiesErr error
	var wg sync.WaitGroup

	// 并行获取三个类型的标签
	wg.Add(3)

	go func() {
		defer wg.Done()
		flavors, flavorsErr = s.tagService.GetTagsByType(models.TagTypeFlavor)
	}()

	go func() {
		defer wg.Done()
		taboos, taboosErr = s.tagService.GetTagsByType(models.TagTypeTaboo)
	}()

	go func() {
		defer wg.Done()
		allergies, allergiesErr = s.tagService.GetTagsByType(models.TagTypeAllergy)
	}()

	wg.Wait()

	// 检查错误
	if flavorsErr != nil {
		return nil, flavorsErr
	}
	if taboosErr != nil {
		return nil, taboosErr
	}
	if allergiesErr != nil {
		return nil, allergiesErr
	}

	return &OptionsResponse{
		Flavors:   convertTagsToOptions(flavors),
		Taboos:    convertTagsToOptions(taboos),
		Allergies: convertTagsToOptions(allergies),
	}, nil
}

// OptionsResponse 偏好选项响应
type OptionsResponse struct {
	Flavors   []OptionItem `json:"flavors"`   // 口味选项
	Taboos    []OptionItem `json:"taboos"`    // 忌口选项
	Allergies []OptionItem `json:"allergies"` // 过敏选项
}

// OptionItem 选项项
type OptionItem struct {
	Value string `json:"value"` // 标签值
	Label string `json:"label"` // 显示名称
}

// convertTagsToOptions 转换标签为选项
func convertTagsToOptions(tags []models.Tag) []OptionItem {
	result := make([]OptionItem, len(tags))
	for i, tag := range tags {
		result[i] = OptionItem{
			Value: tag.Value,
			Label: tag.Label,
		}
	}
	return result
}

// GetUserPreferences 获取用户偏好（包含已选择的选项）
func (s *Service) GetUserPreferences(openid string) (*UserPreferencesResponse, error) {
	// 获取所有选项
	options, err := s.GetOptions()
	if err != nil {
		return nil, err
	}

	// 获取用户已选择的偏好
	var userPrefs []models.UserPreference
	if err := s.db.Where("openid = ?", openid).Find(&userPrefs).Error; err != nil {
		return nil, err
	}

	// 构建已选择的选项集合（用于快速查找）
	selectedMap := make(map[string]bool) // key: "type:value"
	for _, pref := range userPrefs {
		key := string(pref.TagType) + ":" + pref.TagValue
		selectedMap[key] = true
	}

	// 标记已选择的选项
	markSelected := func(options []OptionItem, tagType models.TagType) []OptionItemWithSelected {
		result := make([]OptionItemWithSelected, len(options))
		for i, opt := range options {
			key := string(tagType) + ":" + opt.Value
			result[i] = OptionItemWithSelected{
				Value:    opt.Value,
				Label:    opt.Label,
				Selected: selectedMap[key],
			}
		}
		return result
	}

	return &UserPreferencesResponse{
		Flavors:   markSelected(options.Flavors, models.TagTypeFlavor),
		Taboos:    markSelected(options.Taboos, models.TagTypeTaboo),
		Allergies: markSelected(options.Allergies, models.TagTypeAllergy),
	}, nil
}

// UserPreferencesResponse 用户偏好响应（包含选中状态）
type UserPreferencesResponse struct {
	Flavors   []OptionItemWithSelected `json:"flavors"`   // 口味偏好
	Taboos    []OptionItemWithSelected `json:"taboos"`    // 忌口偏好
	Allergies []OptionItemWithSelected `json:"allergies"` // 过敏偏好
}

// OptionItemWithSelected 带选中状态的选项项
type OptionItemWithSelected struct {
	Value    string `json:"value"`    // 标签值
	Label    string `json:"label"`    // 显示名称
	Selected bool   `json:"selected"` // 是否已选择
}

// UpdateUserPreferences 更新用户偏好（全量替换）
func (s *Service) UpdateUserPreferences(openid string, req *UpdatePreferencesRequest) error {
	// 开始事务
	tx := s.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 删除用户所有现有偏好
	if err := tx.Where("openid = ?", openid).Delete(&models.UserPreference{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// 批量插入新偏好
	prefs := make([]models.UserPreference, 0)

	// 添加口味偏好
	for _, value := range req.Flavors {
		prefs = append(prefs, models.UserPreference{
			OpenID:   openid,
			TagValue: value,
			TagType:  models.TagTypeFlavor,
		})
	}

	// 添加忌口偏好
	for _, value := range req.Taboos {
		prefs = append(prefs, models.UserPreference{
			OpenID:   openid,
			TagValue: value,
			TagType:  models.TagTypeTaboo,
		})
	}

	// 添加过敏偏好
	for _, value := range req.Allergies {
		prefs = append(prefs, models.UserPreference{
			OpenID:   openid,
			TagValue: value,
			TagType:  models.TagTypeAllergy,
		})
	}

	// 批量插入
	if len(prefs) > 0 {
		if err := tx.Create(&prefs).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	// 提交事务
	return tx.Commit().Error
}

// UpdatePreferencesRequest 更新偏好请求
type UpdatePreferencesRequest struct {
	Flavors   []string `json:"flavors"`   // 口味选项值列表
	Taboos    []string `json:"taboos"`    // 忌口选项值列表
	Allergies []string `json:"allergies"` // 过敏选项值列表
}

// Validate 验证请求数据（需要传入 tagService）
func (r *UpdatePreferencesRequest) Validate(tagService *tag.Service) error {
	// 验证口味选项是否存在
	if err := validateTagValues(r.Flavors, models.TagTypeFlavor, tagService); err != nil {
		return err
	}

	// 验证忌口选项是否存在
	if err := validateTagValues(r.Taboos, models.TagTypeTaboo, tagService); err != nil {
		return err
	}

	// 验证过敏选项是否存在
	if err := validateTagValues(r.Allergies, models.TagTypeAllergy, tagService); err != nil {
		return err
	}

	return nil
}

// validateTagValues 验证标签值是否存在
func validateTagValues(values []string, tagType models.TagType, tagService *tag.Service) error {
	if len(values) == 0 {
		return nil
	}

	// 获取该类型的所有标签
	tags, err := tagService.GetTagsByType(tagType)
	if err != nil {
		return err
	}

	// 构建有效值集合
	validValues := make(map[string]bool)
	for _, tag := range tags {
		validValues[tag.Value] = true
	}

	// 验证所有值是否有效
	for _, value := range values {
		if !validValues[value] {
			return &InvalidTagValueError{
				TagType: tagType,
				Value:   value,
			}
		}
	}

	return nil
}

// InvalidTagValueError 无效标签值错误
type InvalidTagValueError struct {
	TagType models.TagType
	Value   string
}

func (e *InvalidTagValueError) Error() string {
	return "无效的标签值: " + string(e.TagType) + ":" + e.Value
}
