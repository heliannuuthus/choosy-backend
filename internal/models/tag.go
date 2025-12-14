package models

// TagType 标签类型
type TagType string

const (
	TagTypeCuisine TagType = "cuisine" // 菜系
	TagTypeFlavor  TagType = "flavor"  // 口味
	TagTypeScene   TagType = "scene"   // 场景
)

// Tag 标签表（直接关联菜谱，无需关联表）
type Tag struct {
	ID       uint    `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	RecipeID string  `gorm:"not null;index;column:recipe_id;size:64" json:"-"`
	Value    string  `gorm:"not null;index;size:50" json:"value"` // sichuan, spicy
	Label    string  `gorm:"not null;size:50" json:"label"`       // 川菜, 香辣
	Type     TagType `gorm:"not null;index;size:20" json:"type"`  // cuisine, flavor, scene
}

func (Tag) TableName() string {
	return "tags"
}
