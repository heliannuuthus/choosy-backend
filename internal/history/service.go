package history

import (
	"errors"
	"strings"
	"time"

	"zwei-backend/internal/models"

	"gorm.io/gorm"
)

// Service 浏览历史服务
type Service struct {
	db *gorm.DB
}

// NewService 创建浏览历史服务
func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// AddViewHistory 添加浏览记录（如果已存在则更新浏览时间）
func (s *Service) AddViewHistory(openID, recipeID string) (*models.ViewHistory, error) {
	var recipe models.Recipe
	if err := s.db.First(&recipe, "recipe_id = ?", recipeID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("菜谱不存在")
		}
		return nil, err
	}

	var existing models.ViewHistory
	err := s.db.Where("openid = ? AND recipe_id = ?", openID, recipeID).
		Order("viewed_at DESC").
		First(&existing).Error

	if err == nil {
		// 已存在，检查距离上次浏览时间是否超过 24 小时
		now := time.Now()
		timeDiff := now.Sub(existing.ViewedAt)

		if timeDiff < 24*time.Hour {
			// 24 小时内，更新浏览时间和更新时间
			existing.ViewedAt = now
			existing.UpdatedAt = now
			if err := s.db.Save(&existing).Error; err != nil {
				return nil, err
			}
			return &existing, nil
		}
		// 超过 24 小时，创建新记录（不更新现有记录）
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// 不存在或超过 24 小时，创建新记录
	now := time.Now()
	history := models.ViewHistory{
		OpenID:    openID,
		RecipeID:  recipeID,
		ViewedAt:  now,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.db.Create(&history).Error; err != nil {
		return nil, err
	}

	return &history, nil
}

// RemoveViewHistory 删除浏览记录
func (s *Service) RemoveViewHistory(openID, recipeID string) error {
	result := s.db.Where("openid = ? AND recipe_id = ?", openID, recipeID).Delete(&models.ViewHistory{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// ClearViewHistory 清空用户的所有浏览记录
func (s *Service) ClearViewHistory(openID string) error {
	result := s.db.Where("openid = ?", openID).Delete(&models.ViewHistory{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// GetViewHistory 获取浏览历史列表
func (s *Service) GetViewHistory(openID, category, search string, limit, offset int) ([]models.ViewHistory, int64, error) {
	var allHistory []models.ViewHistory
	if err := s.db.Where("openid = ?", openID).
		Order("viewed_at DESC").
		Find(&allHistory).Error; err != nil {
		return nil, 0, err
	}

	if len(allHistory) == 0 {
		return []models.ViewHistory{}, 0, nil
	}

	recipeIDs := make([]string, len(allHistory))
	for i, h := range allHistory {
		recipeIDs[i] = h.RecipeID
	}

	var recipes []models.Recipe
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&recipes).Error; err != nil {
		return nil, 0, err
	}

	recipeMap := make(map[string]*models.Recipe)
	for i := range recipes {
		recipeMap[recipes[i].RecipeID] = &recipes[i]
	}

	var filtered []models.ViewHistory
	for i := range allHistory {
		recipe, ok := recipeMap[allHistory[i].RecipeID]
		if !ok {
			continue
		}

		if category != "" && recipe.Category != category {
			continue
		}

		if search != "" {
			searchLower := strings.ToLower(search)
			nameLower := strings.ToLower(recipe.Name)
			descLower := ""
			if recipe.Description != nil {
				descLower = strings.ToLower(*recipe.Description)
			}
			if !strings.Contains(nameLower, searchLower) && !strings.Contains(descLower, searchLower) {
				continue
			}
		}

		allHistory[i].Recipe = recipe
		filtered = append(filtered, allHistory[i])
	}

	total := int64(len(filtered))

	start := offset
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[start:end], total, nil
}
