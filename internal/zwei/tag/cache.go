package tag

import (
	"sync"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/zwei/models"
)

const (
	// 缓存配置
	tagCacheSize        = 1000           // 缓存大小（标签数量通常 < 500）
	tagCacheNumCounters = 10000          // 计数器数量（用于统计）
	tagCacheBufferItems = 64             // 缓冲区大小
	tagCacheTTL         = 24 * time.Hour // TTL：24小时
	// 延迟双删延迟时间（毫秒）
	tagDeleteDelay = 100 * time.Millisecond
)

// tagCache 标签定义缓存（使用 Ristretto + 按类型分组的索引）
type tagCache struct {
	cache *ristretto.Cache[string, any]
	// 按类型分组的索引：map[TagType][]*Tag
	// 使用 sync.Map 因为读多写少，读操作无锁
	typeIndex sync.Map // map[models.TagType][]*models.Tag
	// 保护索引更新的互斥锁（写操作需要加锁）
	indexMu sync.RWMutex
}

var (
	globalTagCache *tagCache
	cacheOnce      sync.Once
)

// getTagCache 获取全局标签缓存实例（内部使用）
func getTagCache() *tagCache {
	cacheOnce.Do(func() {
		// 初始化 Ristretto 缓存
		ristrettoCache, err := ristretto.NewCache(&ristretto.Config[string, any]{
			NumCounters: tagCacheNumCounters,
			MaxCost:     tagCacheSize,
			BufferItems: tagCacheBufferItems,
		})
		if err != nil {
			// 如果缓存初始化失败，创建一个空的缓存结构（降级处理）
			globalTagCache = &tagCache{
				cache: nil,
			}
			return
		}

		// 等待缓存初始化完成
		ristrettoCache.Wait()

		globalTagCache = &tagCache{
			cache: ristrettoCache,
		}
	})
	return globalTagCache
}

// GetTagCache 获取全局标签缓存实例（对外暴露，供其他包使用）
func GetTagCache() *tagCache {
	return getTagCache()
}

// cacheKey 生成缓存 key
func cacheKey(tagType models.TagType, value string) string {
	return string(tagType) + ":" + value
}

// Get 从缓存获取标签定义（懒加载：缓存未命中时查询数据库并设置缓存）
func (c *tagCache) Get(tagType models.TagType, value string, db *gorm.DB) (*models.Tag, error) {
	if c.cache == nil {
		// 降级：直接查询数据库
		var tag models.Tag
		if err := db.Where("type = ? AND value = ?", tagType, value).First(&tag).Error; err != nil {
			return nil, err
		}
		return &tag, nil
	}

	key := cacheKey(tagType, value)
	val, ok := c.cache.Get(key)
	if ok {
		tag, ok := val.(*models.Tag)
		if !ok {
			// 类型转换失败，查询数据库
			return c.loadFromDB(tagType, value, db)
		}
		// 返回副本，避免并发修改
		tagCopy := *tag
		return &tagCopy, nil
	}

	// 缓存未命中，查询数据库并设置缓存
	return c.loadFromDB(tagType, value, db)
}

// loadFromDB 从数据库加载标签并设置到缓存
func (c *tagCache) loadFromDB(tagType models.TagType, value string, db *gorm.DB) (*models.Tag, error) {
	var tag models.Tag
	if err := db.Where("type = ? AND value = ?", tagType, value).First(&tag).Error; err != nil {
		return nil, err
	}

	// 设置到缓存
	c.Set(&tag)
	return &tag, nil
}

// GetByType 从缓存获取指定类型的所有标签（使用索引，无需查询数据库）
func (c *tagCache) GetByType(tagType models.TagType, db *gorm.DB) ([]*models.Tag, error) {
	if c.cache == nil {
		// 降级：直接查询数据库
		var tags []models.Tag
		if err := db.Where("type = ?", tagType).Order("value").Find(&tags).Error; err != nil {
			return nil, err
		}
		result := make([]*models.Tag, len(tags))
		for i := range tags {
			result[i] = &tags[i]
		}
		return result, nil
	}

	// 从索引获取（无锁读，性能最优）
	if tags, ok := c.typeIndex.Load(tagType); ok {
		tagList := tags.([]*models.Tag)
		if len(tagList) == 0 {
			return []*models.Tag{}, nil
		}
		// 返回副本，避免并发修改
		result := make([]*models.Tag, len(tagList))
		for i, tag := range tagList {
			tagCopy := *tag
			result[i] = &tagCopy
		}
		return result, nil
	}

	// 索引未命中，查询数据库并构建索引
	return c.loadTypeIndex(tagType, db)
}

// loadTypeIndex 加载指定类型的索引（需要加锁保护）
func (c *tagCache) loadTypeIndex(tagType models.TagType, db *gorm.DB) ([]*models.Tag, error) {
	// 双重检查，避免并发重复加载
	c.indexMu.RLock()
	if tags, ok := c.typeIndex.Load(tagType); ok {
		c.indexMu.RUnlock()
		tagList := tags.([]*models.Tag)
		result := make([]*models.Tag, len(tagList))
		for i, tag := range tagList {
			tagCopy := *tag
			result[i] = &tagCopy
		}
		return result, nil
	}
	c.indexMu.RUnlock()

	// 加写锁，开始构建索引
	c.indexMu.Lock()
	defer c.indexMu.Unlock()

	// 再次检查（双重检查锁定模式）
	if tags, ok := c.typeIndex.Load(tagType); ok {
		tagList := tags.([]*models.Tag)
		result := make([]*models.Tag, len(tagList))
		for i, tag := range tagList {
			tagCopy := *tag
			result[i] = &tagCopy
		}
		return result, nil
	}

	// 查询数据库获取该类型的所有标签
	var tags []models.Tag
	if err := db.Where("type = ?", tagType).Order("value").Find(&tags).Error; err != nil {
		return nil, err
	}

	// 直接使用查询结果，避免重复查询数据库
	result := make([]*models.Tag, len(tags))
	for i := range tags {
		// 设置到缓存（如果缓存可用）
		if c.cache != nil {
			key := cacheKey(tagType, tags[i].Value)
			c.cache.Set(key, &tags[i], 1)
		}
		result[i] = &tags[i]
	}

	// 更新索引（即使为空也要设置，避免重复查询）
	c.typeIndex.Store(tagType, result)

	return result, nil
}

// GetAll 获取所有标签（按类型分组，使用索引）
func (c *tagCache) GetAll(db *gorm.DB) (map[models.TagType][]*models.Tag, error) {
	if c.cache == nil {
		// 降级：直接查询数据库
		var tags []models.Tag
		if err := db.Order("type, value").Find(&tags).Error; err != nil {
			return nil, err
		}
		result := make(map[models.TagType][]*models.Tag)
		for i := range tags {
			result[tags[i].Type] = append(result[tags[i].Type], &tags[i])
		}
		return result, nil
	}

	// 查询数据库获取所有类型（只需要类型列表，不需要所有标签）
	var tagTypes []models.TagType
	if err := db.Model(&models.Tag{}).Distinct("type").Pluck("type", &tagTypes).Error; err != nil {
		return nil, err
	}

	// 从索引获取每个类型（如果索引未命中，会自动加载）
	result := make(map[models.TagType][]*models.Tag)
	for _, tagType := range tagTypes {
		tags, err := c.GetByType(tagType, db)
		if err != nil {
			// 如果某个类型加载失败，跳过（不影响其他类型）
			continue
		}
		if len(tags) > 0 {
			result[tagType] = tags
		}
	}

	return result, nil
}

// Set 设置标签到缓存（同时更新索引）
func (c *tagCache) Set(tag *models.Tag) {
	if c.cache == nil {
		return
	}

	key := cacheKey(tag.Type, tag.Value)
	c.cache.SetWithTTL(key, tag, 1, tagCacheTTL)

	// 更新索引（需要加锁保护）
	c.updateTypeIndex(tag)
}

// updateTypeIndex 更新类型索引（线程安全）
func (c *tagCache) updateTypeIndex(tag *models.Tag) {
	c.indexMu.Lock()
	defer c.indexMu.Unlock()

	// 获取现有索引
	tags, _ := c.typeIndex.Load(tag.Type)
	var tagList []*models.Tag
	var found bool

	if tags != nil {
		tagList = tags.([]*models.Tag)
		// 检查是否已存在
		for i, t := range tagList {
			if t.Value == tag.Value {
				// 更新现有标签（创建新副本）
				tagCopy := *tag
				tagList[i] = &tagCopy
				found = true
				break
			}
		}
	}

	if !found {
		// 添加新标签
		tagCopy := *tag
		if tagList == nil {
			tagList = []*models.Tag{&tagCopy}
		} else {
			tagList = append(tagList, &tagCopy)
		}
	}

	// 更新索引
	c.typeIndex.Store(tag.Type, tagList)
}

// Delete 从缓存删除标签（同时更新索引）
func (c *tagCache) Delete(tagType models.TagType, value string) {
	if c.cache == nil {
		return
	}

	key := cacheKey(tagType, value)
	c.cache.Del(key)

	// 更新索引（需要加锁保护）
	c.removeFromTypeIndex(tagType, value)
}

// removeFromTypeIndex 从索引中删除标签（线程安全）
func (c *tagCache) removeFromTypeIndex(tagType models.TagType, value string) {
	c.indexMu.Lock()
	defer c.indexMu.Unlock()

	tags, ok := c.typeIndex.Load(tagType)
	if !ok {
		return
	}

	tagList := tags.([]*models.Tag)
	for i, t := range tagList {
		if t.Value == value {
			// 删除该标签
			newList := make([]*models.Tag, 0, len(tagList)-1)
			newList = append(newList, tagList[:i]...)
			newList = append(newList, tagList[i+1:]...)

			if len(newList) == 0 {
				// 如果列表为空，删除该类型的索引
				c.typeIndex.Delete(tagType)
			} else {
				// 更新索引
				c.typeIndex.Store(tagType, newList)
			}
			return
		}
	}
}

// DeleteWithDelay 延迟删除（用于延迟双删的第二次删除）
// 注意：延迟删除不更新索引，因为延迟期间可能已经被重新设置了
func (c *tagCache) DeleteWithDelay(tagType models.TagType, value string, delay time.Duration) {
	if c.cache == nil {
		return
	}

	go func() {
		time.Sleep(delay)
		key := cacheKey(tagType, value)
		c.cache.Del(key)
		// 不更新索引，因为：
		// 1. 延迟期间可能已经被重新设置
		// 2. 如果确实需要删除，下次 GetByType 时会重新加载索引
		// 3. 避免索引和缓存不一致的问题
	}()
}
