package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

var (
	v        *viper.Viper
	mu       sync.RWMutex
	snapshot map[string]any // 配置快照，用于检测变更
)

// Load 加载配置
func Load() {
	if v != nil {
		return
	}

	v = viper.New()

	// 设置配置文件
	v.SetConfigName("config")
	v.SetConfigType("toml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	// 设置环境变量前缀和自动绑定
	v.SetEnvPrefix("CHOOSY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// 特殊处理：APP_ENV 环境变量（不带前缀，直接读取）
	// Dockerfile 设置的 ENV APP_ENV=prod 会直接作为环境变量
	// 也支持 CHOOSY_APP_ENV（通过 AutomaticEnv 自动绑定）
	if appEnv := os.Getenv("APP_ENV"); appEnv != "" {
		v.Set("APP_ENV", appEnv)
	}

	// 读取配置文件
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundErr viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundErr) {
			panic("读取配置文件失败: " + err.Error())
		}
		panic("配置文件不存在，请创建 config.toml")
	}

	// 保存初始快照
	snapshot = v.AllSettings()

	// 启用热更新
	v.WatchConfig()
	v.OnConfigChange(func(e fsnotify.Event) {
		mu.Lock()
		defer mu.Unlock()

		newSettings := v.AllSettings()
		changes := detectChanges("", snapshot, newSettings)

		if len(changes) > 0 {
			fmt.Printf("[config] 配置热更新: %s\n", e.Name)
			for _, change := range changes {
				fmt.Printf("[config]   %s (已更新)\n", change.Key)
			}
		}

		// 更新快照
		snapshot = newSettings
	})
}

// Change 配置变更
type Change struct {
	Key      string
	OldValue any
	NewValue any
}

// detectChanges 检测配置变更
func detectChanges(prefix string, old, new map[string]any) []Change {
	var changes []Change

	// 检查新增和修改的 key
	for k, newVal := range new {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		oldVal, exists := old[k]
		if !exists {
			changes = append(changes, Change{Key: key, OldValue: nil, NewValue: newVal})
			continue
		}

		// 递归检查嵌套 map
		if newMap, ok := newVal.(map[string]any); ok {
			if oldMap, ok := oldVal.(map[string]any); ok {
				changes = append(changes, detectChanges(key, oldMap, newMap)...)
				continue
			}
		}

		// 值比较
		if !reflect.DeepEqual(oldVal, newVal) {
			changes = append(changes, Change{Key: key, OldValue: oldVal, NewValue: newVal})
		}
	}

	// 检查删除的 key
	for k, oldVal := range old {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		if _, exists := new[k]; !exists {
			changes = append(changes, Change{Key: key, OldValue: oldVal, NewValue: nil})
		}
	}

	return changes
}

// V 返回 viper 实例
func V() *viper.Viper {
	if v == nil {
		Load()
	}
	return v
}

// 便捷方法（viper 内部已线程安全）
func GetString(key string) string                     { return V().GetString(key) }
func GetInt(key string) int                           { return V().GetInt(key) }
func GetInt64(key string) int64                       { return V().GetInt64(key) }
func GetBool(key string) bool                         { return V().GetBool(key) }
func GetStringSlice(key string) []string              { return V().GetStringSlice(key) }
func GetStringMap(key string) map[string]any          { return V().GetStringMap(key) }
func GetStringMapString(key string) map[string]string { return V().GetStringMapString(key) }
func GetDuration(key string) time.Duration            { return V().GetDuration(key) }
func Get(key string) any                              { return V().Get(key) }
