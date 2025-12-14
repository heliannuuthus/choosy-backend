package services

import (
	"errors"
	"fmt"

	"choosy-backend/internal/models"

	"gorm.io/gorm"
)

// RecipeService 菜谱服务
type RecipeService struct {
	db *gorm.DB
}

// NewRecipeService 创建菜谱服务
func NewRecipeService(db *gorm.DB) *RecipeService {
	return &RecipeService{db: db}
}

// CreateRecipe 创建菜谱
func (s *RecipeService) CreateRecipe(recipe *models.Recipe, ingredients []models.Ingredient, steps []models.Step, notes []string) error {
	// 检查 ID 是否已存在
	var existing models.Recipe
	if err := s.db.First(&existing, "recipe_id = ?", recipe.RecipeID).Error; err == nil {
		return fmt.Errorf("菜谱 ID '%s' 已存在", recipe.RecipeID)
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		// 创建菜谱主记录
		if err := tx.Create(recipe).Error; err != nil {
			return err
		}

		// 添加食材
		for i := range ingredients {
			ingredients[i].RecipeID = recipe.RecipeID
		}
		if len(ingredients) > 0 {
			if err := tx.Create(&ingredients).Error; err != nil {
				return err
			}
		}

		// 添加步骤
		for i := range steps {
			steps[i].RecipeID = recipe.RecipeID
		}
		if len(steps) > 0 {
			if err := tx.Create(&steps).Error; err != nil {
				return err
			}
		}

		// 添加小贴士
		if len(notes) > 0 {
			additionalNotes := make([]models.AdditionalNote, len(notes))
			for i, note := range notes {
				additionalNotes[i] = models.AdditionalNote{
					RecipeID: recipe.RecipeID,
					Note:     note,
				}
			}
			if err := tx.Create(&additionalNotes).Error; err != nil {
				return err
			}
		}

		return nil
	})
}

// GetRecipe 根据 ID 获取菜谱
func (s *RecipeService) GetRecipe(id string) (*models.Recipe, error) {
	var recipe models.Recipe
	err := s.db.
		Preload("Ingredients").
		Preload("Steps", func(db *gorm.DB) *gorm.DB {
			return db.Order("step ASC")
		}).
		Preload("AdditionalNotes").
		First(&recipe, "recipe_id = ?", id).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// 填充标签
	_ = s.fillTagsForOne(&recipe)

	return &recipe, nil
}

// GetRecipes 获取菜谱列表
func (s *RecipeService) GetRecipes(category, search string, limit, offset int) ([]models.Recipe, error) {
	query := s.db.Model(&models.Recipe{})

	// 按分类筛选
	if category != "" {
		query = query.Where("category = ?", category)
	}

	// 搜索筛选
	if search != "" {
		searchPattern := "%" + search + "%"
		query = query.Where("name LIKE ? OR description LIKE ?", searchPattern, searchPattern)
	}

	var recipes []models.Recipe
	err := query.
		Offset(offset).
		Limit(limit).
		Find(&recipes).Error

	if err != nil {
		return nil, err
	}

	// 填充标签
	_ = s.fillTags(recipes)

	return recipes, nil
}

// RecipeFavoriteCount 菜谱收藏统计
type RecipeFavoriteCount struct {
	RecipeID string
	Count    int
}

// GetHotRecipes 获取热门菜谱（按收藏数排序，service 层计算）
func (s *RecipeService) GetHotRecipes(limit int, excludeIDs []string) ([]models.Recipe, error) {
	// 1. 统计每个菜谱的收藏数
	var counts []RecipeFavoriteCount
	countQuery := s.db.Table("favorites").
		Select("recipe_id, COUNT(*) as count").
		Group("recipe_id").
		Order("count DESC")

	if err := countQuery.Find(&counts).Error; err != nil {
		return nil, err
	}

	if len(counts) == 0 {
		return []models.Recipe{}, nil
	}

	// 2. 构建排除 ID 集合
	excludeMap := make(map[string]bool)
	for _, id := range excludeIDs {
		excludeMap[id] = true
	}

	// 3. 过滤并取前 N 个菜谱 ID
	var recipeIDs []string
	for _, c := range counts {
		if excludeMap[c.RecipeID] {
			continue
		}
		recipeIDs = append(recipeIDs, c.RecipeID)
		if len(recipeIDs) >= limit {
			break
		}
	}

	if len(recipeIDs) == 0 {
		return []models.Recipe{}, nil
	}

	// 4. 批量查询菜谱详情
	var recipes []models.Recipe
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&recipes).Error; err != nil {
		return nil, err
	}

	// 5. 按收藏数顺序排序（保持原有顺序）
	recipeMap := make(map[string]models.Recipe)
	for _, r := range recipes {
		recipeMap[r.RecipeID] = r
	}

	result := make([]models.Recipe, 0, len(recipeIDs))
	for _, id := range recipeIDs {
		if r, ok := recipeMap[id]; ok {
			result = append(result, r)
		}
	}

	// 填充标签
	_ = s.fillTags(result)

	return result, nil
}

// UpdateRecipe 更新菜谱
func (s *RecipeService) UpdateRecipe(id string, updates map[string]interface{}, ingredients []models.Ingredient, steps []models.Step, notes []string, updateIngredients, updateSteps, updateNotes bool) (*models.Recipe, error) {
	// 检查菜谱是否存在
	var recipe models.Recipe
	if err := s.db.First(&recipe, "recipe_id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("菜谱 ID '%s' 不存在", id)
		}
		return nil, err
	}

	return &recipe, s.db.Transaction(func(tx *gorm.DB) error {
		// 更新基本字段
		if len(updates) > 0 {
			if err := tx.Model(&recipe).Updates(updates).Error; err != nil {
				return err
			}
		}

		// 更新食材
		if updateIngredients {
			tx.Where("recipe_id = ?", id).Delete(&models.Ingredient{})
			for i := range ingredients {
				ingredients[i].RecipeID = id
			}
			if len(ingredients) > 0 {
				if err := tx.Create(&ingredients).Error; err != nil {
					return err
				}
			}
		}

		// 更新步骤
		if updateSteps {
			tx.Where("recipe_id = ?", id).Delete(&models.Step{})
			for i := range steps {
				steps[i].RecipeID = id
			}
			if len(steps) > 0 {
				if err := tx.Create(&steps).Error; err != nil {
					return err
				}
			}
		}

		// 更新小贴士
		if updateNotes {
			tx.Where("recipe_id = ?", id).Delete(&models.AdditionalNote{})
			if len(notes) > 0 {
				additionalNotes := make([]models.AdditionalNote, len(notes))
				for i, note := range notes {
					additionalNotes[i] = models.AdditionalNote{
						RecipeID: id,
						Note:     note,
					}
				}
				if err := tx.Create(&additionalNotes).Error; err != nil {
					return err
				}
			}
		}

		// 重新加载菜谱
		return tx.
			Preload("Ingredients").
			Preload("Steps", func(db *gorm.DB) *gorm.DB {
				return db.Order("step ASC")
			}).
			Preload("AdditionalNotes").
			First(&recipe, "recipe_id = ?", id).Error
	})
}

// DeleteRecipe 删除菜谱
func (s *RecipeService) DeleteRecipe(id string) error {
	var recipe models.Recipe
	if err := s.db.First(&recipe, "recipe_id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("菜谱 ID '%s' 不存在", id)
		}
		return err
	}

	return s.db.Delete(&recipe).Error
}

// GetCategories 获取所有分类
func (s *RecipeService) GetCategories() ([]string, error) {
	var categories []string
	err := s.db.Model(&models.Recipe{}).
		Distinct("category").
		Where("category IS NOT NULL AND category != ''").
		Pluck("category", &categories).Error
	return categories, err
}

// GetCategoriesWithCount 获取所有分类及其数量
func (s *RecipeService) GetCategoriesWithCount() (map[string]int64, error) {
	type Result struct {
		Category string
		Count    int64
	}

	var results []Result
	err := s.db.Model(&models.Recipe{}).
		Select("category, COUNT(*) as count").
		Where("category IS NOT NULL AND category != ''").
		Group("category").
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	counts := make(map[string]int64)
	for _, r := range results {
		counts[r.Category] = r.Count
	}
	return counts, nil
}

// CreateRecipesBatch 批量创建菜谱
func (s *RecipeService) CreateRecipesBatch(recipes []models.Recipe, ingredientsList [][]models.Ingredient, stepsList [][]models.Step, notesList [][]string) ([]models.Recipe, error) {
	var created []models.Recipe

	for i := range recipes {
		var ingredients []models.Ingredient
		var steps []models.Step
		var notes []string

		if i < len(ingredientsList) {
			ingredients = ingredientsList[i]
		}
		if i < len(stepsList) {
			steps = stepsList[i]
		}
		if i < len(notesList) {
			notes = notesList[i]
		}

		if err := s.CreateRecipe(&recipes[i], ingredients, steps, notes); err != nil {
			// 跳过失败的记录
			continue
		}
		created = append(created, recipes[i])
	}

	return created, nil
}

// fillTags 批量填充菜谱的标签
func (s *RecipeService) fillTags(recipes []models.Recipe) error {
	if len(recipes) == 0 {
		return nil
	}

	// 收集所有菜谱 ID
	recipeIDs := make([]string, len(recipes))
	for i, r := range recipes {
		recipeIDs[i] = r.RecipeID
	}

	// 直接查询 tags 表
	var tags []models.Tag
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&tags).Error; err != nil {
		return err
	}

	// 构建 recipeID -> []Tag 映射
	recipeTagsMap := make(map[string][]models.Tag)
	for _, t := range tags {
		recipeTagsMap[t.RecipeID] = append(recipeTagsMap[t.RecipeID], t)
	}

	// 填充到菜谱
	for i := range recipes {
		recipes[i].Tags = recipeTagsMap[recipes[i].RecipeID]
	}

	return nil
}

// fillTagsForOne 填充单个菜谱的标签
func (s *RecipeService) fillTagsForOne(recipe *models.Recipe) error {
	if recipe == nil {
		return nil
	}
	recipes := []models.Recipe{*recipe}
	if err := s.fillTags(recipes); err != nil {
		return err
	}
	recipe.Tags = recipes[0].Tags
	return nil
}
