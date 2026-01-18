package kms

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"zwei-backend/internal/config"
	"zwei-backend/internal/logger"
)

var (
	dbEncKey []byte
	dbOnce   sync.Once
	dbErr    error
)

// GetDBEncKey 获取数据库加密密钥
func GetDBEncKey() ([]byte, error) {
	dbOnce.Do(func() {
		keyStr := config.GetString("kms.database.enc-key")
		if keyStr == "" {
			dbErr = errors.New("kms.database.enc-key 未配置")
			return
		}

		key, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			dbErr = fmt.Errorf("解码数据库加密密钥失败: %w", err)
			return
		}

		if len(key) != 32 {
			dbErr = fmt.Errorf("数据库加密密钥长度错误: 期望 32 字节, 实际 %d 字节", len(key))
			return
		}

		dbEncKey = key
		logger.Info("[KMS] 数据库加密密钥加载成功")
	})

	return dbEncKey, dbErr
}

// EncryptPhone 加密手机号（用于存储和展示）
// openid 作为 AAD，确保密文与用户绑定
func EncryptPhone(phone string, openid string) (string, error) {
	key, err := GetDBEncKey()
	if err != nil {
		return "", err
	}
	return Encrypt(key, phone, openid)
}

// DecryptPhone 解密手机号
// openid 作为 AAD，必须与加密时一致
func DecryptPhone(encrypted string, openid string) (string, error) {
	key, err := GetDBEncKey()
	if err != nil {
		return "", err
	}
	return Decrypt(key, encrypted, openid)
}

// EncryptSensitive 加密敏感数据（通用）
// aad 作为附加认证数据，可为空
func EncryptSensitive(plaintext string, aad string) (string, error) {
	key, err := GetDBEncKey()
	if err != nil {
		return "", err
	}
	return Encrypt(key, plaintext, aad)
}

// DecryptSensitive 解密敏感数据（通用）
func DecryptSensitive(encrypted string, aad string) (string, error) {
	key, err := GetDBEncKey()
	if err != nil {
		return "", err
	}
	return Decrypt(key, encrypted, aad)
}
