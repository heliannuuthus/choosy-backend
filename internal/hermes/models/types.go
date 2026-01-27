package models

import (
	"github.com/heliannuuthus/helios/pkg/json"
)

// ApplicationWithKey 带解密密钥的 Application
type ApplicationWithKey struct {
	Application
	Key []byte // 解密后的密钥（如果存在）
}

// GetRedirectURIs 解析重定向 URI 列表
func (a *ApplicationWithKey) GetRedirectURIs() []string {
	if a.RedirectURIs == nil || *a.RedirectURIs == "" {
		return nil
	}
	var uris []string
	_ = json.Unmarshal([]byte(*a.RedirectURIs), &uris)
	return uris
}

// ValidateRedirectURI 验证重定向 URI
func (a *ApplicationWithKey) ValidateRedirectURI(uri string) bool {
	for _, r := range a.GetRedirectURIs() {
		if r == uri {
			return true
		}
	}
	return false
}

// ServiceWithKey 带解密密钥的 Service
type ServiceWithKey struct {
	Service
	Key []byte // 解密后的密钥
}

// DomainWithKey 带签名密钥的 Domain
type DomainWithKey struct {
	Domain
	SignKey []byte // 签名密钥
}
