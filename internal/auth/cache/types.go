package cache

import (
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// ServiceWithKey 带解密密钥的 Service
type ServiceWithKey struct {
	models.Service
	Key []byte // 解密后的密钥
}

// ApplicationWithKey 带解密密钥的 Application
type ApplicationWithKey struct {
	models.Application
	Key []byte // 解密后的密钥（如果存在）
}

// DomainWithKey 带解密密钥的 Domain
type DomainWithKey struct {
	models.Domain
	SignKey    []byte // 签名密钥
	EncryptKey []byte // 加密密钥
}
