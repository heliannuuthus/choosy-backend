package database

import (
	"fmt"
	"time"

	"zwei-backend/internal/config"
	"zwei-backend/internal/logger"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var db *gorm.DB

// Init 初始化数据库连接
func Init() *gorm.DB {
	if db != nil {
		return db
	}

	// 从配置读取 MySQL 连接信息
	host := config.GetString("database.host")
	if host == "" {
		host = "localhost"
	}
	port := config.GetInt("database.port")
	if port == 0 {
		port = 3306
	}
	user := config.GetString("database.user")
	if user == "" {
		user = "zwei"
	}
	password := config.GetString("database.password")
	if password == "" {
		password = "zwei"
	}
	database := config.GetString("database.name")
	if database == "" {
		database = "zwei"
	}

	// 构建 MySQL DSN
	// 添加连接超时和读写超时参数，避免 unexpected EOF
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local&timeout=10s&readTimeout=30s&writeTimeout=30s",
		user, password, host, port, database)

	// 配置 GORM 日志（只打印错误）
	logLevel := gormlogger.Error

	// 使用 zap 作为 GORM 的日志
	gormLog := gormlogger.New(
		logger.GormWriter(),
		gormlogger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logLevel,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: gormLog,
	})
	if err != nil {
		logger.Fatalf("连接数据库失败: %v", err)
	}

	// 配置连接池
	sqlDB, err := db.DB()
	if err != nil {
		logger.Fatalf("获取数据库连接失败: %v", err)
	}

	// 设置连接池参数
	sqlDB.SetMaxIdleConns(10)           // 最大空闲连接数
	sqlDB.SetMaxOpenConns(30)           // 最大打开连接数
	sqlDB.SetConnMaxLifetime(time.Hour) // 连接最大生存时间

	logger.Info("数据库连接成功")
	return db
}

// Get 获取数据库连接
func Get() *gorm.DB {
	if db == nil {
		return Init()
	}
	return db
}
