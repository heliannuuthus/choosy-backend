package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Client OAuth2 客户端
type Client struct {
	ID                    uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	Domain                Domain    `gorm:"column:domain;size:32;not null;index"`
	ClientID              string    `gorm:"column:client_id;size:64;not null;uniqueIndex"`
	Name                  string    `gorm:"column:name;size:128;not null"`
	RedirectURIs          string    `gorm:"column:redirect_uris;type:text"` // JSON 数组
	AccessTokenExpiresIn  int       `gorm:"column:access_token_expires_in;default:7200"`
	RefreshTokenExpiresIn int       `gorm:"column:refresh_token_expires_in;default:604800"`
	CreatedAt             time.Time `gorm:"column:created_at"`
	UpdatedAt             time.Time `gorm:"column:updated_at"`
}

func (Client) TableName() string {
	return "t_client"
}

// GetRedirectURIs 解析重定向 URI 列表
func (c *Client) GetRedirectURIs() []string {
	if c.RedirectURIs == "" {
		return nil
	}
	var uris []string
	_ = json.Unmarshal([]byte(c.RedirectURIs), &uris)
	return uris
}

// SetRedirectURIs 设置重定向 URI 列表
func (c *Client) SetRedirectURIs(uris []string) {
	if len(uris) == 0 {
		c.RedirectURIs = ""
		return
	}
	data, _ := json.Marshal(uris)
	c.RedirectURIs = string(data)
}

// ValidateRedirectURI 验证重定向 URI
func (c *Client) ValidateRedirectURI(uri string) bool {
	for _, r := range c.GetRedirectURIs() {
		if r == uri {
			return true
		}
	}
	return false
}

// ValidateIDP 验证 IDP 是否允许（IDP 配置从配置文件读取）
func (c *Client) ValidateIDP(idp IDP) bool {
	// IDP 所属域必须匹配
	return idp.GetDomain() == c.Domain
}

// SupportsGrantType 检查客户端是否支持指定的 grant type
func (c *Client) SupportsGrantType(grantType GrantType) bool {
	// TODO: 从数据库读取 GrantTypes 字段
	// 目前默认只支持 authorization_code
	return grantType == GrantTypeAuthorizationCode
}

// GenerateClientID 生成客户端 ID
func GenerateClientID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
