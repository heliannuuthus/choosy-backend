package models

import "time"

// TagType 标签类型
type TagType string

const (
	TagTypeCuisine TagType = "cuisine" // 菜系
	TagTypeFlavor  TagType = "flavor"  // 口味
	TagTypeScene   TagType = "scene"   // 场景
	TagTypeTaboo   TagType = "taboo"   // 忌口（用户偏好选项）
	TagTypeAllergy TagType = "allergy" // 过敏（用户偏好选项）
)

// Tag 标签表（独立存储，不关联菜谱）
// 存储所有标签定义，包括菜谱标签和用户偏好选项
type Tag struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	Value     string    `gorm:"not null;index;size:50" json:"value"` // 标签值
	Label     string    `gorm:"not null;size:50" json:"label"`       // 显示名称
	Type      TagType   `gorm:"not null;index;size:20" json:"type"`  // 类型
	CreatedAt time.Time `gorm:"not null;column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at" json:"updated_at"`
}

func (Tag) TableName() string {
	return "t_tag"
}

// IsOption 判断是否为选项（用户偏好选项）
func (t *Tag) IsOption() bool {
	return t.Type == TagTypeTaboo || t.Type == TagTypeAllergy
}

// RecipeTag 菜谱标签关联表
// 存储菜谱和标签的多对多关系
type RecipeTag struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	RecipeID  string    `gorm:"not null;index;column:recipe_id;size:32" json:"-"` // 关联 t_recipe.recipe_id
	TagValue  string    `gorm:"not null;index;column:tag_value;size:50" json:"-"` // 关联 t_tag.value
	TagType   TagType   `gorm:"not null;index;column:tag_type;size:20" json:"-"`  // 关联 t_tag.type（冗余字段，优化查询）
	CreatedAt time.Time `gorm:"not null;column:created_at" json:"created_at"`
}

func (RecipeTag) TableName() string {
	return "t_recipe_tag"
}
