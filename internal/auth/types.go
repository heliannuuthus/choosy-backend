package auth

// Identity 用户身份信息（JWE 内层加密内容）
type Identity struct {
	OpenID   string `json:"sub"`
	Nickname string `json:"nickname,omitempty"`
	Avatar   string `json:"picture,omitempty"`
}

// GetOpenID 返回系统生成的 openid
func (u *Identity) GetOpenID() string {
	return u.OpenID
}

// TokenPair token 对
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// JWK 密钥结构
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x,omitempty"`
	D   string `json:"d,omitempty"`
	K   string `json:"k,omitempty"`
}

// WxCode2SessionResponse 微信 code2session 响应
type WxCode2SessionResponse struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid,omitempty"`
	ErrCode    int    `json:"errcode,omitempty"`
	ErrMsg     string `json:"errmsg,omitempty"`
}

// TtCode2SessionResponse TT code2session 响应
type TtCode2SessionResponse struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid,omitempty"`
	ErrCode    int    `json:"errcode,omitempty"`
	ErrMsg     string `json:"errmsg,omitempty"`
}

// AlipayCode2SessionResponse 支付宝 code2session 响应
type AlipayCode2SessionResponse struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid,omitempty"`
	ErrCode    string `json:"code,omitempty"`    // 支付宝使用 code 字段表示错误码
	ErrMsg     string `json:"msg,omitempty"`     // 支付宝使用 msg 字段表示错误信息
	SubMsg     string `json:"sub_msg,omitempty"` // 支付宝子错误信息
}

// IdP 常量
const (
	IDPWechatMP      = "wechat:mp"      // 微信小程序
	IDPWechatUnionID = "wechat:unionid" // 微信 UnionID
	IDPWechatOA      = "wechat:oa"      // 微信公众号
	IDPTTMP          = "tt:mp"          // TT 小程序
	IDPTTUnionID     = "tt:unionid"     // TT UnionID
	IDPAlipayMP      = "alipay:mp"      // 支付宝小程序
	IDPAppleSignIn   = "apple:signin"   // Apple 登录
)
