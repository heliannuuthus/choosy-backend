package models

import (
	"time"
)

// Favorite 收藏表
type Favorite struct {
	ID        string    `gorm:"primaryKey;column:id;size:32" json:"id"`
	OpenID    string    `gorm:"not null;index:idx_favorite_user;column:openid;size:64" json:"-"`
	RecipeID  string    `gorm:"not null;index:idx_favorite_recipe;column:recipe_id;size:64" json:"recipe_id"`
	CreatedAt time.Time `gorm:"not null;column:created_at" json:"created_at"`

	// 关联关系
	Recipe *Recipe `gorm:"foreignKey:RecipeID;references:ID" json:"recipe,omitempty"`
}

func (Favorite) TableName() string {
	return "favorites"
}
