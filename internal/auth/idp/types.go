package idp

// IDP 类型常量
const (
	// CIAM 域
	TypeWechatMP = "wechat:mp" // 微信小程序
	TypeTTMP     = "tt:mp"     // 抖音小程序
	TypeAlipayMP = "alipay:mp" // 支付宝小程序

	// PIAM 域
	TypeWecom  = "wecom"  // 企业微信
	TypeGithub = "github" // GitHub
	TypeGoogle = "google" // Google
)

// Domain 用户域
type Domain string

const (
	DomainCIAM Domain = "ciam" // Customer Identity（C 端用户）
	DomainPIAM Domain = "piam" // Partner/Employee Identity（B 端用户）
)

// GetDomain 获取 IDP 所属域
func GetDomain(idpType string) Domain {
	switch idpType {
	case TypeWecom, TypeGithub, TypeGoogle:
		return DomainPIAM
	default:
		return DomainCIAM
	}
}

// SupportsAutoCreate 是否支持自动创建用户
func SupportsAutoCreate(idpType string) bool {
	switch idpType {
	case TypeWechatMP, TypeTTMP, TypeAlipayMP:
		return true // C 端都支持
	default:
		return false // B 端需要预先配置
	}
}
