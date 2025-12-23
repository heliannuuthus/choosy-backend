package favorite

import (
	"errors"
	"strings"
	"time"

	"choosy-backend/internal/models"

	"gorm.io/gorm"
)

// Service 收藏服务
type Service struct {
	db *gorm.DB
}

// NewService 创建收藏服务
func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// AddFavorite 添加收藏
func (s *Service) AddFavorite(openID, recipeID string) (*models.Favorite, error) {
	var recipe models.Recipe
	if err := s.db.First(&recipe, "recipe_id = ?", recipeID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("菜谱不存在")
		}
		return nil, err
	}

	var existing models.Favorite
	err := s.db.Where("openid = ? AND recipe_id = ?", openID, recipeID).First(&existing).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	favorite := models.Favorite{
		OpenID:    openID,
		RecipeID:  recipeID,
		CreatedAt: time.Now(),
	}

	if err := s.db.Create(&favorite).Error; err != nil {
		return nil, err
	}

	return &favorite, nil
}

// RemoveFavorite 取消收藏
func (s *Service) RemoveFavorite(openID, recipeID string) error {
	result := s.db.Where("openid = ? AND recipe_id = ?", openID, recipeID).Delete(&models.Favorite{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// IsFavorite 检查是否已收藏
func (s *Service) IsFavorite(openID, recipeID string) (bool, error) {
	var count int64
	err := s.db.Model(&models.Favorite{}).Where("openid = ? AND recipe_id = ?", openID, recipeID).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetFavorites 获取收藏列表
func (s *Service) GetFavorites(openID, category, search string, limit, offset int) ([]models.Favorite, int64, error) {
	var allFavorites []models.Favorite
	if err := s.db.Where("openid = ?", openID).
		Order("created_at DESC").
		Find(&allFavorites).Error; err != nil {
		return nil, 0, err
	}

	if len(allFavorites) == 0 {
		return []models.Favorite{}, 0, nil
	}

	recipeIDs := make([]string, len(allFavorites))
	for i, f := range allFavorites {
		recipeIDs[i] = f.RecipeID
	}

	var recipes []models.Recipe
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&recipes).Error; err != nil {
		return nil, 0, err
	}

	recipeMap := make(map[string]*models.Recipe)
	for i := range recipes {
		recipeMap[recipes[i].RecipeID] = &recipes[i]
	}

	var filtered []models.Favorite
	for i := range allFavorites {
		recipe, ok := recipeMap[allFavorites[i].RecipeID]
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

		allFavorites[i].Recipe = recipe
		filtered = append(filtered, allFavorites[i])
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

// GetFavoriteRecipeIDs 批量检查收藏状态
func (s *Service) GetFavoriteRecipeIDs(openID string, recipeIDs []string) ([]string, error) {
	var favorites []models.Favorite
	err := s.db.Select("recipe_id").
		Where("openid = ? AND recipe_id IN ?", openID, recipeIDs).
		Find(&favorites).Error

	if err != nil {
		return nil, err
	}

	result := make([]string, len(favorites))
	for i, f := range favorites {
		result[i] = f.RecipeID
	}

	return result, nil
}

