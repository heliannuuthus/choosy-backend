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
	ID               string      `gorm:"primaryKey;column:id" json:"id"`
	Name             string      `gorm:"not null;index" json:"name"`
	Description      *string     `gorm:"type:text" json:"description"`
	SourcePath       *string     `gorm:"column:source_path" json:"source_path"`
	ImagePath        *string     `gorm:"column:image_path" json:"image_path"`
	Images           StringSlice `gorm:"type:json;default:'[]'" json:"images"`
	Category         string      `gorm:"index" json:"category"`
	Difficulty       int         `json:"difficulty"`
	Tags             StringSlice `gorm:"type:json;default:'[]'" json:"tags"`
	Servings         int         `json:"servings"`
	PrepTimeMinutes  *int        `gorm:"column:prep_time_minutes" json:"prep_time_minutes"`
	CookTimeMinutes  *int        `gorm:"column:cook_time_minutes" json:"cook_time_minutes"`
	TotalTimeMinutes *int        `gorm:"column:total_time_minutes" json:"total_time_minutes"`

	// 关联关系
	Ingredients     []Ingredient     `gorm:"foreignKey:RecipeID;constraint:OnDelete:CASCADE" json:"ingredients"`
	Steps           []Step           `gorm:"foreignKey:RecipeID;constraint:OnDelete:CASCADE" json:"steps"`
	AdditionalNotes []AdditionalNote `gorm:"foreignKey:RecipeID;constraint:OnDelete:CASCADE" json:"additional_notes"`
}

func (Recipe) TableName() string {
	return "recipes"
}

// Ingredient 食材表
type Ingredient struct {
	ID           uint     `gorm:"primaryKey;autoIncrement" json:"id"`
	RecipeID     string   `gorm:"not null;index;column:recipe_id" json:"-"`
	Name         string   `gorm:"not null" json:"name"`
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
	ID          uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	RecipeID    string `gorm:"not null;index;column:recipe_id" json:"-"`
	Step        int    `gorm:"not null" json:"step"`
	Description string `gorm:"not null;type:text" json:"description"`
}

func (Step) TableName() string {
	return "steps"
}

// AdditionalNote 小贴士表
type AdditionalNote struct {
	ID       uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	RecipeID string `gorm:"not null;index;column:recipe_id" json:"-"`
	Note     string `gorm:"not null;type:text" json:"note"`
}

func (AdditionalNote) TableName() string {
	return "additional_notes"
}
