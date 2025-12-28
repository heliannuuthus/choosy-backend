package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// StringSlice JSON 存储的字符串数组
type StringSlice []string

func (s StringSlice) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	return json.Marshal(s)
}

func (s *StringSlice) Scan(value interface{}) error {
	if value == nil {
		*s = []string{}
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return errors.New("无法将值转换为 StringSlice")
	}

	return json.Unmarshal(bytes, s)
}

// Recipe 菜谱表
type Recipe struct {
	ID               uint        `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	RecipeID         string      `gorm:"uniqueIndex;not null;column:recipe_id;size:32" json:"id"`
	Name             string      `gorm:"uniqueIndex;not null;size:128" json:"name"`
	Description      *string     `gorm:"type:text" json:"description"`
	Images           StringSlice `gorm:"type:json;default:'[]'" json:"images"`
	Category         string      `gorm:"index" json:"category"`
	Difficulty       int         `json:"difficulty"`
	Servings         int         `json:"servings"`
	PrepTimeMinutes  *int        `gorm:"column:prep_time_minutes" json:"prep_time_minutes"`
	CookTimeMinutes  *int        `gorm:"column:cook_time_minutes" json:"cook_time_minutes"`
	TotalTimeMinutes *int        `gorm:"column:total_time_minutes" json:"total_time_minutes"`

	// 关联关系（无外键约束，在应用层处理，使用 recipe_id 作为关联字段）
	Ingredients     []Ingredient     `gorm:"foreignKey:RecipeID;references:RecipeID" json:"ingredients"`
	Steps           []Step           `gorm:"foreignKey:RecipeID;references:RecipeID" json:"steps"`
	AdditionalNotes []AdditionalNote `gorm:"foreignKey:RecipeID;references:RecipeID" json:"additional_notes"`
	Tags            []Tag            `gorm:"-" json:"tags"` // 不自动 JOIN，在 service 层手动填充
}

// GetImagePath 获取主图路径（images 数组第一张）
func (r *Recipe) GetImagePath() *string {
	if len(r.Images) > 0 {
		return &r.Images[0]
	}
	return nil
}

func (Recipe) TableName() string {
	return "recipes"
}

// Ingredient 食材表
type Ingredient struct {
	ID           uint     `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	RecipeID     string   `gorm:"not null;index;column:recipe_id" json:"-"`
	Name         string   `gorm:"not null" json:"name"`
	Category     *string  `gorm:"index" json:"category"`
	Quantity     *float64 `json:"quantity"`
	Unit         *string  `json:"unit"`
	TextQuantity string   `gorm:"not null;column:text_quantity" json:"text_quantity"`
	Notes        *string  `json:"notes"`
}

func (Ingredient) TableName() string {
	return "ingredients"
}

// Step 步骤表
type Step struct {
	ID          uint   `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	RecipeID    string `gorm:"not null;index;column:recipe_id" json:"-"`
	Step        int    `gorm:"not null" json:"step"`
	Description string `gorm:"not null;type:text" json:"description"`
}

func (Step) TableName() string {
	return "steps"
}

// AdditionalNote 小贴士表
type AdditionalNote struct {
	ID       uint   `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	RecipeID string `gorm:"not null;index;column:recipe_id" json:"-"`
	Note     string `gorm:"not null;type:text" json:"note"`
}

func (AdditionalNote) TableName() string {
	return "additional_notes"
}
