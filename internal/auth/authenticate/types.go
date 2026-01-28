package authenticate

// AuthType 认证类型
type AuthType string

const (
	AuthTypeIDP   AuthType = "idp"   // 第三方登录
	AuthTypeEmail AuthType = "email" // 邮箱验证码
)

// AuthResult 认证结果
type AuthResult struct {
	ProviderID string // 认证源侧用户标识
	UnionID    string // 联合 ID（可选）
	RawData    string // 原始数据
}
