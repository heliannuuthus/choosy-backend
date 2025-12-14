package services

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"choosy-backend/internal/models"

	"gorm.io/gorm"
)

// FavoriteService 收藏服务
type FavoriteService struct {
	db *gorm.DB
}

// NewFavoriteService 创建收藏服务
func NewFavoriteService(db *gorm.DB) *FavoriteService {
	return &FavoriteService{db: db}
}

// generateFavoriteID 生成收藏 ID
func generateFavoriteID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// AddFavorite 添加收藏
func (s *FavoriteService) AddFavorite(openID, recipeID string) (*models.Favorite, error) {
	// 检查菜谱是否存在
	var recipe models.Recipe
	if err := s.db.First(&recipe, "recipe_id = ?", recipeID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("菜谱不存在")
		}
		return nil, err
	}

	// 检查是否已收藏
	var existing models.Favorite
	err := s.db.Where("openid = ? AND recipe_id = ?", openID, recipeID).First(&existing).Error
	if err == nil {
		// 已收藏，返回现有记录
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// 创建收藏（ID 自增，无需手动设置）
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
func (s *FavoriteService) RemoveFavorite(openID, recipeID string) error {
	result := s.db.Where("openid = ? AND recipe_id = ?", openID, recipeID).Delete(&models.Favorite{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// IsFavorite 检查是否已收藏
func (s *FavoriteService) IsFavorite(openID, recipeID string) (bool, error) {
	var count int64
	err := s.db.Model(&models.Favorite{}).Where("openid = ? AND recipe_id = ?", openID, recipeID).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetFavorites 获取收藏列表（支持搜索，分步查询无 JOIN）
func (s *FavoriteService) GetFavorites(openID, category, search string, limit, offset int) ([]models.Favorite, int64, error) {
	// 1. 查询用户所有收藏（按时间倒序）
	var allFavorites []models.Favorite
	if err := s.db.Where("openid = ?", openID).
		Order("created_at DESC").
		Find(&allFavorites).Error; err != nil {
		return nil, 0, err
	}

	if len(allFavorites) == 0 {
		return []models.Favorite{}, 0, nil
	}

	// 2. 提取所有 recipe_ids
	recipeIDs := make([]string, len(allFavorites))
	for i, f := range allFavorites {
		recipeIDs[i] = f.RecipeID
	}

	// 3. 批量查询菜谱详情
	var recipes []models.Recipe
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&recipes).Error; err != nil {
		return nil, 0, err
	}

	// 4. 构建菜谱 map
	recipeMap := make(map[string]*models.Recipe)
	for i := range recipes {
		recipeMap[recipes[i].RecipeID] = &recipes[i]
	}

	// 5. 在内存中筛选和关联
	var filtered []models.Favorite
	for i := range allFavorites {
		recipe, ok := recipeMap[allFavorites[i].RecipeID]
		if !ok {
			continue
		}

		// 分类筛选
		if category != "" && recipe.Category != category {
			continue
		}

		// 搜索筛选
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

		// 关联菜谱信息
		allFavorites[i].Recipe = recipe
		filtered = append(filtered, allFavorites[i])
	}

	// 6. 计算总数
	total := int64(len(filtered))

	// 7. 内存分页
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
func (s *FavoriteService) GetFavoriteRecipeIDs(openID string, recipeIDs []string) ([]string, error) {
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
