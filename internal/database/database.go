package database

import (
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/logger"
)

var (
	zweiDB *gorm.DB // Zwei 数据源（业务数据）
	authDB *gorm.DB // Auth 数据源（认证数据）
)

// connectDB 连接数据库的通用方法
func connectDB(dataSource string) (*gorm.DB, error) {
	// 从配置读取 MySQL 连接信息
	host := config.GetString(fmt.Sprintf("database.%s.host", dataSource))
	if host == "" {
		host = config.GetString("database.host") // 兼容旧配置
		if host == "" {
			host = "localhost"
		}
	}
	port := config.GetInt(fmt.Sprintf("database.%s.port", dataSource))
	if port == 0 {
		port = config.GetInt("database.port") // 兼容旧配置
		if port == 0 {
			port = 3306
		}
	}
	user := config.GetString(fmt.Sprintf("database.%s.user", dataSource))
	if user == "" {
		user = config.GetString("database.user") // 兼容旧配置
		if user == "" {
			user = "zwei"
		}
	}
	password := config.GetString(fmt.Sprintf("database.%s.password", dataSource))
	if password == "" {
		password = config.GetString("database.password") // 兼容旧配置
		if password == "" {
			password = "zwei"
		}
	}
	database := config.GetString(fmt.Sprintf("database.%s.name", dataSource))
	if database == "" {
		// 如果没有指定，使用默认值
		switch dataSource {
		case "zwei":
			database = config.GetString("database.name")
			if database == "" {
				database = "zwei"
			}
		case "auth":
			database = "auth"
		}
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

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: gormLog,
	})
	if err != nil {
		return nil, fmt.Errorf("连接数据库失败 (%s): %w", dataSource, err)
	}

	// 配置连接池
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("获取数据库连接失败 (%s): %w", dataSource, err)
	}

	// 设置连接池参数
	sqlDB.SetMaxIdleConns(10)           // 最大空闲连接数
	sqlDB.SetMaxOpenConns(30)           // 最大打开连接数
	sqlDB.SetConnMaxLifetime(time.Hour) // 连接最大生存时间

	logger.Infof("数据库连接成功 (%s): %s@%s:%d/%s", dataSource, user, host, port, database)
	return db, nil
}

// Init 初始化所有数据库连接
func Init() {
	InitZwei()
	InitAuth()
}

// InitZwei 初始化 Zwei 数据源（业务数据）
func InitZwei() *gorm.DB {
	if zweiDB != nil {
		return zweiDB
	}

	var err error
	zweiDB, err = connectDB("zwei")
	if err != nil {
		logger.Fatalf("%v", err)
	}
	return zweiDB
}

// InitAuth 初始化 Auth 数据源（认证数据）
func InitAuth() *gorm.DB {
	if authDB != nil {
		return authDB
	}

	var err error
	authDB, err = connectDB("auth")
	if err != nil {
		logger.Fatalf("%v", err)
	}
	return authDB
}

// GetZwei 获取 Zwei 数据库连接
func GetZwei() *gorm.DB {
	if zweiDB == nil {
		return InitZwei()
	}
	return zweiDB
}

// GetAuth 获取 Auth 数据库连接
func GetAuth() *gorm.DB {
	if authDB == nil {
		return InitAuth()
	}
	return authDB
}

// Get 获取数据库连接（兼容旧代码，返回 Zwei 数据源）
// Deprecated: 请使用 GetZwei() 或 GetAuth() 明确指定数据源
func Get() *gorm.DB {
	return GetZwei()
}
