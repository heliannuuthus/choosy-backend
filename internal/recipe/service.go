package recipe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"zwei-backend/internal/models"
	"zwei-backend/internal/tag"

	"github.com/dgraph-io/ristretto"
	"gorm.io/gorm"
)

const (
	categoriesCacheKey = "categories"
	cacheMaxCost       = 100              // 最大成本（分类数据很小，100 足够）
	cacheNumCounters   = 1000             // 计数器数量（用于统计）
	cacheBufferItems   = 64               // 缓冲区大小
	refreshInterval    = 10 * time.Minute // 刷新间隔
	refreshTimeout     = 5 * time.Second  // 刷新超时时间
)

// categoryCacheRefresher 分类缓存刷新器（内聚的刷新逻辑）
type categoryCacheRefresher struct {
	db            *gorm.DB
	cache         *ristretto.Cache
	refreshMutex  sync.Mutex
	isRefreshing  bool
	refreshTicker *time.Ticker
	stopChan      chan struct{}
}

// newCategoryCacheRefresher 创建分类缓存刷新器
func newCategoryCacheRefresher(db *gorm.DB, cache *ristretto.Cache) *categoryCacheRefresher {
	return &categoryCacheRefresher{
		db:       db,
		cache:    cache,
		stopChan: make(chan struct{}),
	}
}

// doRefresh 执行实际的刷新操作（同步）
func (r *categoryCacheRefresher) doRefresh(ctx context.Context) error {
	var categories []string
	err := r.db.WithContext(ctx).Model(&models.Recipe{}).
		Distinct("category").
		Where("category IS NOT NULL AND category != ''").
		Pluck("category", &categories).Error

	if err == nil {
		r.cache.SetWithTTL(categoriesCacheKey, categories, 1, 30*time.Minute)
	}
	return err
}

// refresh 异步刷新分类缓存（非阻塞）
func (r *categoryCacheRefresher) refresh() {
	if r.cache == nil {
		return
	}

	// 检查是否正在刷新，避免并发刷新
	r.refreshMutex.Lock()
	if r.isRefreshing {
		r.refreshMutex.Unlock()
		return
	}
	r.isRefreshing = true
	r.refreshMutex.Unlock()

	// 异步执行刷新，不阻塞
	go func() {
		defer func() {
			r.refreshMutex.Lock()
			r.isRefreshing = false
			r.refreshMutex.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
		defer cancel()
		_ = r.doRefresh(ctx)
	}()
}

// start 启动定期刷新
func (r *categoryCacheRefresher) start() {
	if r.cache == nil {
		return
	}

	// 首次同步刷新，确保启动时有数据
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	_ = r.doRefresh(ctx)
	cancel()

	// 启动定期刷新协程
	r.refreshTicker = time.NewTicker(refreshInterval)
	go func() {
		for {
			select {
			case <-r.refreshTicker.C:
				r.refresh()
			case <-r.stopChan:
				return
			}
		}
	}()
}

// Service 菜谱服务
type Service struct {
	db                     *gorm.DB
	categoriesCache        *ristretto.Cache
	categoryCacheRefresher *categoryCacheRefresher
}

// NewService 创建菜谱服务
func NewService(db *gorm.DB) *Service {
	s := &Service{db: db}

	// 初始化 Ristretto 缓存
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: cacheNumCounters,
		MaxCost:     cacheMaxCost,
		BufferItems: cacheBufferItems,
	})
	if err != nil {
		// 如果缓存初始化失败，继续运行但不使用缓存
		return s
	}
	s.categoriesCache = cache

	// 等待缓存初始化完成
	s.categoriesCache.Wait()

	// 创建并启动分类缓存刷新器
	s.categoryCacheRefresher = newCategoryCacheRefresher(db, cache)
	s.categoryCacheRefresher.start()

	return s
}

// CreateRecipe 创建菜谱
func (s *Service) CreateRecipe(recipe *models.Recipe, ingredients []models.Ingredient, steps []models.Step, notes []string) error {
	var existing models.Recipe
	if err := s.db.First(&existing, "recipe_id = ?", recipe.RecipeID).Error; err == nil {
		return fmt.Errorf("菜谱 ID '%s' 已存在", recipe.RecipeID)
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(recipe).Error; err != nil {
			return err
		}

		for i := range ingredients {
			ingredients[i].RecipeID = recipe.RecipeID
		}
		if len(ingredients) > 0 {
			if err := tx.Create(&ingredients).Error; err != nil {
				return err
			}
		}

		for i := range steps {
			steps[i].RecipeID = recipe.RecipeID
		}
		if len(steps) > 0 {
			if err := tx.Create(&steps).Error; err != nil {
				return err
			}
		}

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
func (s *Service) GetRecipe(id string) (*models.Recipe, error) {
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

	_ = s.fillTagsForOne(&recipe)

	return &recipe, nil
}

// GetRecipes 获取菜谱列表
func (s *Service) GetRecipes(category, search string, limit, offset int) ([]models.Recipe, error) {
	query := s.db.Model(&models.Recipe{})

	if category != "" {
		query = query.Where("category = ?", category)
	}

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

	_ = s.fillTags(recipes)

	return recipes, nil
}

// FavoriteCount 菜谱收藏统计
type FavoriteCount struct {
	RecipeID string
	Count    int
}

// GetHotRecipes 获取热门菜谱（按收藏数排序）
func (s *Service) GetHotRecipes(limit int, excludeIDs []string) ([]models.Recipe, error) {
	var counts []FavoriteCount
	countQuery := s.db.Model(&models.Favorite{}).
		Select("recipe_id, COUNT(*) as count").
		Group("recipe_id").
		Order("count DESC")

	if err := countQuery.Find(&counts).Error; err != nil {
		return nil, err
	}

	if len(counts) == 0 {
		return []models.Recipe{}, nil
	}

	excludeMap := make(map[string]bool)
	for _, id := range excludeIDs {
		excludeMap[id] = true
	}

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

	var recipes []models.Recipe
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&recipes).Error; err != nil {
		return nil, err
	}

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

	_ = s.fillTags(result)

	return result, nil
}

// UpdateRecipe 更新菜谱
func (s *Service) UpdateRecipe(id string, updates map[string]interface{}, ingredients []models.Ingredient, steps []models.Step, notes []string, updateIngredients, updateSteps, updateNotes bool) (*models.Recipe, error) {
	var recipe models.Recipe
	if err := s.db.First(&recipe, "recipe_id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("菜谱 ID '%s' 不存在", id)
		}
		return nil, err
	}

	return &recipe, s.db.Transaction(func(tx *gorm.DB) error {
		if len(updates) > 0 {
			if err := tx.Model(&recipe).Updates(updates).Error; err != nil {
				return err
			}
		}

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
func (s *Service) DeleteRecipe(id string) error {
	var recipe models.Recipe
	if err := s.db.First(&recipe, "recipe_id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("菜谱 ID '%s' 不存在", id)
		}
		return err
	}

	return s.db.Delete(&recipe).Error
}

// GetCategories 获取所有分类（从缓存获取，缓存未命中时查询数据库）
func (s *Service) GetCategories() ([]string, error) {
	// 尝试从缓存获取
	if s.categoriesCache != nil {
		if cached, found := s.categoriesCache.Get(categoriesCacheKey); found {
			if categories, ok := cached.([]string); ok {
				return categories, nil
			}
		}
	}

	// 缓存未命中，查询数据库
	var categories []string
	err := s.db.Model(&models.Recipe{}).
		Distinct("category").
		Where("category IS NOT NULL AND category != ''").
		Pluck("category", &categories).Error

	if err == nil && s.categoriesCache != nil {
		// 更新缓存，TTL=30分钟
		s.categoriesCache.SetWithTTL(categoriesCacheKey, categories, 1, 30*time.Minute)
	}

	return categories, err
}

// GetCategoriesWithCount 获取所有分类及其数量
func (s *Service) GetCategoriesWithCount() (map[string]int64, error) {
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
func (s *Service) CreateRecipesBatch(recipes []models.Recipe, ingredientsList [][]models.Ingredient, stepsList [][]models.Step, notesList [][]string) ([]models.Recipe, error) {
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
			continue
		}
		created = append(created, recipes[i])
	}

	return created, nil
}

func (s *Service) fillTags(recipes []models.Recipe) error {
	if len(recipes) == 0 {
		return nil
	}

	recipeIDs := make([]string, len(recipes))
	for i, r := range recipes {
		recipeIDs[i] = r.RecipeID
	}

	// 1. 查询关联表（不 JOIN，避免连表查询）
	var recipeTags []models.RecipeTag
	if err := s.db.Where("recipe_id IN ?", recipeIDs).Find(&recipeTags).Error; err != nil {
		return err
	}

	if len(recipeTags) == 0 {
		// 没有标签，直接返回空
		for i := range recipes {
			recipes[i].Tags = []models.Tag{}
		}
		return nil
	}

	// 2. 从缓存获取标签定义（懒加载：缓存未命中时自动查询数据库）
	tagCache := tag.GetTagCache()

	// 3. 按 recipe_id 分组组装（从缓存获取标签定义）
	recipeTagsMap := make(map[string][]models.Tag)
	for _, rt := range recipeTags {
		tag, err := tagCache.Get(rt.TagType, rt.TagValue, s.db)
		if err == nil {
			recipeTagsMap[rt.RecipeID] = append(recipeTagsMap[rt.RecipeID], *tag)
		}
	}

	// 6. 填充到 recipes
	for i := range recipes {
		if tags, ok := recipeTagsMap[recipes[i].RecipeID]; ok {
			recipes[i].Tags = tags
		} else {
			recipes[i].Tags = []models.Tag{}
		}
	}

	return nil
}

func (s *Service) fillTagsForOne(recipe *models.Recipe) error {
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
