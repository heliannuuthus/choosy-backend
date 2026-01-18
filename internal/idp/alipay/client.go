package alipay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/tidwall/gjson"

	"zwei-backend/internal/config"
	"zwei-backend/internal/logger"
)

// Code2SessionResponse 支付宝 code2session 响应
type Code2SessionResponse struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid,omitempty"`
	ErrCode    string `json:"code,omitempty"`    // 支付宝使用 code 字段表示错误码
	ErrMsg     string `json:"msg,omitempty"`     // 支付宝使用 msg 字段表示错误信息
	SubMsg     string `json:"sub_msg,omitempty"` // 支付宝子错误信息
}

// UserInfoResponse 支付宝用户信息响应
type UserInfoResponse struct {
	NickName string `json:"nick_name"` // 昵称
	Avatar   string `json:"avatar"`    // 头像 URL
	Gender   string `json:"gender"`    // 性别：m-男，f-女
	Province string `json:"province"`  // 省份
	City     string `json:"city"`      // 城市
}

// Client 支付宝客户端
type Client struct{}

// NewClient 创建支付宝客户端
func NewClient() *Client {
	return &Client{}
}

// parsePrivateKey 解析 RSA 私钥（支持 PEM 和 DER Base64 格式）
func parsePrivateKey(privateKeyData string) (*rsa.PrivateKey, error) {
	var keyBytes []byte
	var err error

	// 尝试解析为 PEM 格式
	block, _ := pem.Decode([]byte(privateKeyData))
	if block != nil {
		// PEM 格式
		keyBytes = block.Bytes
	} else {
		// 尝试解析为 DER Base64 格式
		keyBytes, err = base64.StdEncoding.DecodeString(privateKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key (not PEM or Base64): %w", err)
		}
	}

	var priv *rsa.PrivateKey

	// 尝试 PKCS8 格式
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err == nil {
		var ok bool
		priv, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return priv, nil
	}

	// 尝试 PKCS1 格式
	priv, err = x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (tried PKCS8 and PKCS1): %w", err)
	}

	return priv, nil
}

// parsePublicKey 解析 RSA 公钥（支持 PEM 和 DER Base64 格式）
func parsePublicKey(publicKeyData string) (*rsa.PublicKey, error) {
	var keyBytes []byte
	var err error

	// 尝试解析为 PEM 格式
	block, _ := pem.Decode([]byte(publicKeyData))
	if block != nil {
		// PEM 格式
		keyBytes = block.Bytes
	} else {
		// 尝试解析为 DER Base64 格式
		keyBytes, err = base64.StdEncoding.DecodeString(publicKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key (not PEM or Base64): %w", err)
		}
	}

	// 解析公钥
	pub, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

// buildSignContent 构建待签名字符串
// 注意：待签名字符串中的参数值不进行 URL 编码，保持原样
// 只有在最后发送请求时才对 sign 值进行 URL 编码
func buildSignContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		// 排除 sign 本身和空值参数，sign_type 需要参与签名
		if k == "sign" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var items []string
	for _, k := range keys {
		// 直接拼接，不进行 URL 编码（支付宝签名规则要求）
		items = append(items, fmt.Sprintf("%s=%s", k, params[k]))
	}
	return strings.Join(items, "&")
}

// signWithRSA2 使用 RSA2 算法签名
func signWithRSA2(privateKey *rsa.PrivateKey, data string) (string, error) {
	h := sha256.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}

// verifySign 验证支付宝响应签名
func verifySign(publicKey *rsa.PublicKey, signData, sign string) error {
	signBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return fmt.Errorf("failed to decode sign: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(signData))
	hashed := h.Sum(nil)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signBytes)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// Code2Session 调用支付宝 alipay.system.oauth.token 接口
func (c *Client) Code2Session(code string) (*Code2SessionResponse, error) {
	appid := config.GetString("idps.alipay.appid")
	privateKeyData := config.GetString("idps.alipay.secret")
	if appid == "" || privateKeyData == "" {
		return nil, errors.New("支付宝小程序 IdP 未配置")
	}

	logger.Infof("[Alipay] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 解析应用私钥
	privateKey, err := parsePrivateKey(privateKeyData)
	if err != nil {
		logger.Errorf("[Alipay] 解析私钥失败: %v", err)
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}

	// 构建请求参数
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	params := map[string]string{
		"app_id":     appid,
		"method":     "alipay.system.oauth.token",
		"format":     "JSON",
		"charset":    "utf-8",
		"sign_type":  "RSA2",
		"timestamp":  timestamp,
		"version":    "1.0",
		"grant_type": "authorization_code",
		"code":       code,
	}

	// 构建签名字符串（sign_type 需要参与签名）
	signContent := buildSignContent(params)
	logger.Debugf("[Alipay] 待签名字符串: %s", signContent)
	sign, err := signWithRSA2(privateKey, signContent)
	if err != nil {
		logger.Errorf("[Alipay] 签名失败: %v", err)
		return nil, fmt.Errorf("签名失败: %w", err)
	}
	params["sign"] = sign

	// 构建 POST 请求
	// 注意：form.Encode() 会自动对参数值进行 URL 编码，这是正确的
	form := url.Values{}
	for k, v := range params {
		form.Add(k, v)
	}

	req, err := http.NewRequest("POST", "https://openapi.alipay.com/gateway.do", strings.NewReader(form.Encode()))
	if err != nil {
		logger.Errorf("[Alipay] 构建请求失败: %v", err)
		return nil, fmt.Errorf("构建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("[Alipay] 请求接口失败: %v", err)
		return nil, fmt.Errorf("请求接口失败: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("[Alipay] 读取响应失败: %v", err)
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	bodyStr := string(bodyBytes)
	logger.Infof("[Alipay] 响应: %s", bodyStr)

	// 检查是否有错误响应
	errorCode := gjson.Get(bodyStr, "error_response.code").String()
	if errorCode != "" {
		errorMsg := gjson.Get(bodyStr, "error_response.msg").String()
		subCode := gjson.Get(bodyStr, "error_response.sub_code").String()
		subMsg := gjson.Get(bodyStr, "error_response.sub_msg").String()
		logger.Errorf("[Alipay] 登录失败 - Code: %s, Msg: %s, SubCode: %s, SubMsg: %s", errorCode, errorMsg, subCode, subMsg)
		return nil, fmt.Errorf("登录失败: %s - %s", errorMsg, subMsg)
	}

	// 验证响应签名（如果配置了支付宝公钥）
	alipayPublicKeyData := config.GetString("idps.alipay.verify-key")
	if alipayPublicKeyData != "" {
		alipayPublicKey, err := parsePublicKey(alipayPublicKeyData)
		if err != nil {
			logger.Warnf("[Alipay] 解析公钥失败，跳过签名验证: %v", err)
		} else {
			// 提取响应签名
			sign := gjson.Get(bodyStr, "sign").String()
			if sign == "" {
				logger.Warnf("[Alipay] 响应中缺少签名，跳过验证")
			} else {
				// 支付宝响应签名验证：使用原始 JSON 字符串进行验签
				// 注意：必须保持原始字段顺序和格式，不能手动构建
				// 验签时直接使用 alipay_system_oauth_token_response 对象的原始 JSON 字符串
				responseNode := gjson.Get(bodyStr, "alipay_system_oauth_token_response")
				if responseNode.Exists() {
					// 使用 Raw 获取原始 JSON 字符串（保持字段顺序和格式）
					// responseRaw 已经是完整的 JSON 对象字符串，如 {"user_id":"...","access_token":"..."}
					responseRaw := responseNode.Raw
					logger.Debugf("[Alipay] 待验证签名字符串: %s", responseRaw)
					logger.Debugf("[Alipay] 响应签名: %s", sign)

					err = verifySign(alipayPublicKey, responseRaw, sign)
					if err != nil {
						logger.Errorf("[Alipay] 响应签名验证失败: %v", err)
						logger.Debugf("[Alipay] 待验证签名字符串: %s", responseRaw)
						return nil, fmt.Errorf("响应签名验证失败: %w", err)
					}
					logger.Infof("[Alipay] 响应签名验证成功")
				} else {
					logger.Warnf("[Alipay] 响应中缺少响应体，跳过签名验证")
				}
			}
		}
	} else {
		logger.Warnf("[Alipay] 未配置支付宝公钥，跳过响应签名验证")
	}

	// 解析成功响应
	responseNode := gjson.Get(bodyStr, "alipay_system_oauth_token_response")
	if !responseNode.Exists() {
		logger.Errorf("[Alipay] 响应中缺少 alipay_system_oauth_token_response")
		logger.Debugf("[Alipay] 完整响应内容: %s", bodyStr)
		return nil, errors.New("响应中缺少 alipay_system_oauth_token_response")
	}

	// 提取用户ID（使用 open_id 字段）
	userID := gjson.Get(bodyStr, "alipay_system_oauth_token_response.open_id").String()
	accessToken := gjson.Get(bodyStr, "alipay_system_oauth_token_response.access_token").String()

	if userID == "" {
		logger.Errorf("[Alipay] 响应中缺少 open_id 字段")
		logger.Debugf("[Alipay] 响应体内容: %s", responseNode.Raw)
		// 输出所有字段以便调试
		responseMap := responseNode.Map()
		logger.Debugf("[Alipay] 响应体所有字段: %v", responseMap)
		return nil, errors.New("响应中缺少 open_id 字段")
	}

	logger.Infof("[Alipay] 登录成功 - UserID: %s", userID)

	return &Code2SessionResponse{
		OpenID:     userID,      // 支付宝使用 user_id 作为 openid
		SessionKey: accessToken, // 支付宝使用 access_token 作为 session_key
	}, nil
}

// GetUserInfo 获取支付宝用户信息（昵称、头像等）
// 注意：此方法已废弃，支付宝小程序推荐使用前端"获取头像昵称"组件
// 前端通过 button open-type="chooseAvatar" 和 input type="nickname" 获取用户信息
// 然后直接传给后端，后端无需再调用此接口
// Deprecated: 使用前端组件获取用户信息，直接传给后端
func (c *Client) GetUserInfo(accessToken string) (*UserInfoResponse, error) {
	appid := config.GetString("idps.alipay.appid")
	privateKeyData := config.GetString("idps.alipay.secret")
	if appid == "" || privateKeyData == "" {
		return nil, errors.New("支付宝小程序 IdP 未配置")
	}

	logger.Debugf("[Alipay] 获取用户信息 - AccessToken: %s...", accessToken[:min(len(accessToken), 10)])

	// 解析应用私钥
	privateKey, err := parsePrivateKey(privateKeyData)
	if err != nil {
		logger.Errorf("[Alipay] 解析私钥失败: %v", err)
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}

	// 构建请求参数
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	params := map[string]string{
		"app_id":     appid,
		"method":     "alipay.user.info.share",
		"format":     "JSON",
		"charset":    "utf-8",
		"sign_type":  "RSA2",
		"timestamp":  timestamp,
		"version":    "1.0",
		"auth_token": accessToken,
	}

	// 构建签名字符串
	signContent := buildSignContent(params)
	logger.Debugf("[Alipay] 待签名字符串: %s", signContent)
	sign, err := signWithRSA2(privateKey, signContent)
	if err != nil {
		logger.Errorf("[Alipay] 签名失败: %v", err)
		return nil, fmt.Errorf("签名失败: %w", err)
	}
	params["sign"] = sign

	// 构建 POST 请求
	form := url.Values{}
	for k, v := range params {
		form.Add(k, v)
	}

	req, err := http.NewRequest("POST", "https://openapi.alipay.com/gateway.do", strings.NewReader(form.Encode()))
	if err != nil {
		logger.Errorf("[Alipay] 构建请求失败: %v", err)
		return nil, fmt.Errorf("构建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("[Alipay] 请求接口失败: %v", err)
		return nil, fmt.Errorf("请求接口失败: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("[Alipay] 读取响应失败: %v", err)
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	bodyStr := string(bodyBytes)
	logger.Debugf("[Alipay] 用户信息响应: %s", bodyStr)

	// 检查是否有错误响应
	errorCode := gjson.Get(bodyStr, "error_response.code").String()
	if errorCode != "" {
		errorMsg := gjson.Get(bodyStr, "error_response.msg").String()
		subCode := gjson.Get(bodyStr, "error_response.sub_code").String()
		subMsg := gjson.Get(bodyStr, "error_response.sub_msg").String()
		logger.Errorf("[Alipay] 获取用户信息失败 - Code: %s, Msg: %s, SubCode: %s, SubMsg: %s", errorCode, errorMsg, subCode, subMsg)
		return nil, fmt.Errorf("获取用户信息失败: %s - %s", errorMsg, subMsg)
	}

	// 验证响应签名（如果配置了支付宝公钥）
	alipayPublicKeyData := config.GetString("idps.alipay.verify-key")
	if alipayPublicKeyData != "" {
		alipayPublicKey, err := parsePublicKey(alipayPublicKeyData)
		if err != nil {
			logger.Warnf("[Alipay] 解析公钥失败，跳过签名验证: %v", err)
		} else {
			sign := gjson.Get(bodyStr, "sign").String()
			if sign != "" {
				responseNode := gjson.Get(bodyStr, "alipay_user_info_share_response")
				if responseNode.Exists() {
					responseRaw := responseNode.Raw
					err = verifySign(alipayPublicKey, responseRaw, sign)
					if err != nil {
						logger.Errorf("[Alipay] 响应签名验证失败: %v", err)
						return nil, fmt.Errorf("响应签名验证失败: %w", err)
					}
					logger.Debugf("[Alipay] 用户信息响应签名验证成功")
				}
			}
		}
	}

	// 解析成功响应
	responseNode := gjson.Get(bodyStr, "alipay_user_info_share_response")
	if !responseNode.Exists() {
		logger.Errorf("[Alipay] 响应中缺少 alipay_user_info_share_response")
		return nil, errors.New("响应中缺少 alipay_user_info_share_response")
	}

	userInfo := &UserInfoResponse{
		NickName: gjson.Get(bodyStr, "alipay_user_info_share_response.nick_name").String(),
		Avatar:   gjson.Get(bodyStr, "alipay_user_info_share_response.avatar").String(),
		Gender:   gjson.Get(bodyStr, "alipay_user_info_share_response.gender").String(),
		Province: gjson.Get(bodyStr, "alipay_user_info_share_response.province").String(),
		City:     gjson.Get(bodyStr, "alipay_user_info_share_response.city").String(),
	}

	logger.Infof("[Alipay] 获取用户信息成功 - NickName: %s", userInfo.NickName)

	return userInfo, nil
}

// GetPhoneNumber 获取支付宝手机号
func (c *Client) GetPhoneNumber(code string) (string, error) {
	// 支付宝获取手机号需要 RSA 签名，比较复杂
	// 这里先返回未实现错误，后续可以完善
	logger.Warnf("[Alipay] 支付宝获取手机号暂未完全实现，需要 RSA 签名")
	return "", errors.New("支付宝获取手机号暂未完全实现，需要配置 RSA 密钥和实现签名逻辑")
}
