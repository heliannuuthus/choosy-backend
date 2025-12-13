//go:build ignore
// +build ignore

// 数据库迁移脚本
// 运行: go run scripts/migrate.go
package main

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
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

// User 用户信息
type User struct {
	ID        string    `gorm:"primaryKey;column:_id;size:32"`
	OpenID    string    `gorm:"not null;uniqueIndex;column:openid;size:64"`
	TOpenID   string    `gorm:"not null;uniqueIndex;column:t_openid;size:64"`
	Nickname  string    `gorm:"not null;column:nickname;size:64"`
	Avatar    string    `gorm:"not null;column:avatar;size:512"`
	CreatedAt time.Time `gorm:"not null;column:created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at"`
}

func (User) TableName() string {
	return "users"
}

// RefreshToken 刷新令牌
type RefreshToken struct {
	ID        string    `gorm:"primaryKey;column:_id;size:32"`
	OpenID    string    `gorm:"not null;index;column:openid;size:64"`
	Token     string    `gorm:"not null;uniqueIndex;size:128"`
	ExpiresAt time.Time `gorm:"not null;column:expires_at"`
	CreatedAt time.Time `gorm:"not null;column:created_at"`
	UpdatedAt time.Time `gorm:"not null;column:updated_at"`
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

// Recipe 菜谱
type Recipe struct {
	ID               string      `gorm:"primaryKey;column:id"`
	Name             string      `gorm:"not null;index"`
	Description      *string     `gorm:"type:text"`
	SourcePath       *string     `gorm:"column:source_path"`
	ImagePath        *string     `gorm:"column:image_path"`
	Images           StringSlice `gorm:"type:json;default:'[]'"`
	Category         string      `gorm:"index"`
	Difficulty       int
	Tags             StringSlice `gorm:"type:json;default:'[]'"`
	Servings         int
	PrepTimeMinutes  *int `gorm:"column:prep_time_minutes"`
	CookTimeMinutes  *int `gorm:"column:cook_time_minutes"`
	TotalTimeMinutes *int `gorm:"column:total_time_minutes"`
}

func (Recipe) TableName() string {
	return "recipes"
}

// Ingredient 食材
type Ingredient struct {
	ID           uint   `gorm:"primaryKey;autoIncrement"`
	RecipeID     string `gorm:"not null;index;column:recipe_id"`
	Name         string `gorm:"not null"`
	Quantity     *float64
	Unit         *string
	TextQuantity string `gorm:"not null;column:text_quantity"`
	Notes        *string
}

func (Ingredient) TableName() string {
	return "ingredients"
}

// Step 步骤
type Step struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	RecipeID    string `gorm:"not null;index;column:recipe_id"`
	Step        int    `gorm:"not null"`
	Description string `gorm:"not null;type:text"`
}

func (Step) TableName() string {
	return "steps"
}

// AdditionalNote 小贴士
type AdditionalNote struct {
	ID       uint   `gorm:"primaryKey;autoIncrement"`
	RecipeID string `gorm:"not null;index;column:recipe_id"`
	Note     string `gorm:"not null;type:text"`
}

func (AdditionalNote) TableName() string {
	return "additional_notes"
}

// Favorite 收藏
type Favorite struct {
	ID        string    `gorm:"primaryKey;column:id;size:32"`
	OpenID    string    `gorm:"not null;index:idx_favorite_user;column:openid;size:64"`
	RecipeID  string    `gorm:"not null;index:idx_favorite_recipe;column:recipe_id;size:64"`
	CreatedAt time.Time `gorm:"not null;column:created_at"`
}

func (Favorite) TableName() string {
	return "favorites"
}

func main() {
	// 数据库路径
	dbPath := "db/choosy.db"
	if len(os.Args) > 1 {
		dbPath = os.Args[1]
	}

	// 确保目录存在
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("创建目录失败: %v", err)
		}
	}

	// 连接数据库
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Info),
	})
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}

	fmt.Printf("正在迁移数据库: %s\n", dbPath)

	// 执行迁移
	if err := db.AutoMigrate(
		&User{},
		&RefreshToken{},
		&Recipe{},
		&Ingredient{},
		&Step{},
		&AdditionalNote{},
		&Favorite{},
	); err != nil {
		log.Fatalf("迁移失败: %v", err)
	}

	fmt.Println("✓ 迁移完成")

	// 打印表信息
	var tables []string
	db.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables)
	fmt.Printf("当前表: %v\n", tables)
}
