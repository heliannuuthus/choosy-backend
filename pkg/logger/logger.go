package logger

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Log   *zap.Logger
	Sugar *zap.SugaredLogger
)

// Config 日志配置
type Config struct {
	Format string // json 或 console
	Level  string // debug, info, warn, error
	Debug  bool   // 是否为调试模式
}

// InitWithConfig 使用配置初始化日志
func InitWithConfig(cfg Config) {
	var zapCfg zap.Config

	// 根据 format 选择编码器
	format := strings.ToLower(cfg.Format)
	if format == "json" {
		zapCfg = zap.NewProductionConfig()
		zapCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		// console 格式
		zapCfg = zap.NewDevelopmentConfig()
		zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		zapCfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006/01/02 15:04:05")
	}

	// 设置日志级别
	level := strings.ToLower(cfg.Level)
	switch level {
	case "debug":
		zapCfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case "info":
		zapCfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	case "warn", "warning":
		zapCfg.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case "error":
		zapCfg.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	default:
		// 未配置时根据 debug 模式决定
		if cfg.Debug {
			zapCfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
		} else {
			zapCfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
		}
	}

	// 输出到 stdout
	zapCfg.OutputPaths = []string{"stdout"}
	zapCfg.ErrorOutputPaths = []string{"stderr"}

	var err error
	Log, err = zapCfg.Build(zap.AddCallerSkip(1))
	if err != nil {
		panic(err)
	}

	Sugar = Log.Sugar()
}

// Sync 刷新日志缓冲
func Sync() {
	if Log != nil {
		if err := Log.Sync(); err != nil {
			// 忽略同步错误，因为日志系统不应该因为同步失败而崩溃
		}
	}
}

// Debug 调试日志
func Debug(msg string, fields ...zap.Field) {
	Log.Debug(msg, fields...)
}

// Info 信息日志
func Info(msg string, fields ...zap.Field) {
	Log.Info(msg, fields...)
}

// Warn 警告日志
func Warn(msg string, fields ...zap.Field) {
	Log.Warn(msg, fields...)
}

// Error 错误日志
func Error(msg string, fields ...zap.Field) {
	Log.Error(msg, fields...)
}

// Fatal 致命错误日志（会退出程序）
func Fatal(msg string, fields ...zap.Field) {
	Log.Fatal(msg, fields...)
}

// Debugf 格式化调试日志
func Debugf(template string, args ...interface{}) {
	Sugar.Debugf(template, args...)
}

// Infof 格式化信息日志
func Infof(template string, args ...interface{}) {
	Sugar.Infof(template, args...)
}

// Warnf 格式化警告日志
func Warnf(template string, args ...interface{}) {
	Sugar.Warnf(template, args...)
}

// Errorf 格式化错误日志
func Errorf(template string, args ...interface{}) {
	Sugar.Errorf(template, args...)
}

// Fatalf 格式化致命错误日志
func Fatalf(template string, args ...interface{}) {
	Sugar.Fatalf(template, args...)
}

// WithFields 添加字段
func WithFields(fields ...zap.Field) *zap.Logger {
	return Log.With(fields...)
}

// GormWriter 返回 GORM 兼容的日志 writer
func GormWriter() *GormLogWriter {
	return &GormLogWriter{}
}

// GormLogWriter GORM 日志写入器
type GormLogWriter struct{}

func (w *GormLogWriter) Printf(format string, args ...interface{}) {
	Sugar.Infof(format, args...)
}

func init() {
	// 确保即使没调用 Init 也能用（使用默认 logger）
	if Log == nil {
		var err error
		Log, err = zap.NewDevelopment()
		if err != nil {
			panic(fmt.Sprintf("init logger failed: %v", err))
		}
		Sugar = Log.Sugar()
	}
}

// S 方便在没有 zap.Field 时使用
func S() *zap.SugaredLogger {
	return Sugar
}

// L 获取原始 logger
func L() *zap.Logger {
	return Log
}

// Exit 优雅退出
func Exit(code int) {
	Sync()
	os.Exit(code)
}
