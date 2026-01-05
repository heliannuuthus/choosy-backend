package models

import (
	"time"
)

// ViewHistory 浏览历史表
type ViewHistory struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"-"`
	OpenID    string    `gorm:"not null;index:idx_view_history_user;column:openid;size:64" json:"-"`
	RecipeID  string    `gorm:"not null;index:idx_view_history_recipe;column:recipe_id;size:64" json:"recipe_id"`
	ViewedAt  time.Time `gorm:"not null;column:viewed_at" json:"viewed_at"`
	CreatedAt time.Time `gorm:"not null;column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at" json:"updated_at"`

	// 关联关系（仅用于查询，非物理外键）
	Recipe *Recipe `gorm:"foreignKey:RecipeID;references:RecipeID" json:"recipe,omitempty"`
}

func (ViewHistory) TableName() string {
	return "view_history"
}
