package cache

import (
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/json"
)

// Service 带解密密钥的 Service
type Service struct {
	models.Service
	Key []byte // 解密后的密钥
}

// Application 带解密密钥的 Application
type Application struct {
	models.Application
	Key []byte // 解密后的密钥（如果存在）
}

// GetRedirectURIs 解析重定向 URI 列表
func (a *Application) GetRedirectURIs() []string {
	if a.RedirectURIs == nil || *a.RedirectURIs == "" {
		return nil
	}
	var uris []string
	_ = json.Unmarshal([]byte(*a.RedirectURIs), &uris)
	return uris
}

// ValidateRedirectURI 验证重定向 URI
func (a *Application) ValidateRedirectURI(uri string) bool {
	for _, r := range a.GetRedirectURIs() {
		if r == uri {
			return true
		}
	}
	return false
}

// Domain 带签名密钥的 Domain
type Domain struct {
	models.Domain
	SignKey []byte // 签名密钥
}
