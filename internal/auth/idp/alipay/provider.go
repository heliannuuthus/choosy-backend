package alipay

import (
	"context"
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

	"github.com/heliannuuthus/helios/internal/auth/idp"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Provider 支付宝小程序 Provider
type Provider struct {
	appID      string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey // 支付宝公钥，用于验签
}

// NewProvider 创建支付宝 Provider
func NewProvider() *Provider {
	p := &Provider{
		appID: config.GetString("idps.alipay.appid"),
	}

	// 解析私钥
	privateKeyData := config.GetString("idps.alipay.secret")
	if privateKeyData != "" {
		privateKey, err := parsePrivateKey(privateKeyData)
		if err != nil {
			logger.Errorf("[Alipay] 解析私钥失败: %v", err)
		} else {
			p.privateKey = privateKey
		}
	}

	// 解析公钥（可选，用于验签）
	publicKeyData := config.GetString("idps.alipay.verify-key")
	if publicKeyData != "" {
		publicKey, err := parsePublicKey(publicKeyData)
		if err != nil {
			logger.Warnf("[Alipay] 解析公钥失败，跳过签名验证: %v", err)
		} else {
			p.publicKey = publicKey
		}
	}

	return p
}

// Type 返回 IDP 类型
func (*Provider) Type() string {
	return idp.TypeAlipayMP
}

// Exchange 用 code 换取用户信息
func (p *Provider) Exchange(ctx context.Context, code string) (*idp.ExchangeResult, error) {
	if p.appID == "" || p.privateKey == nil {
		return nil, errors.New("支付宝小程序 IdP 未配置")
	}

	logger.Infof("[Alipay] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 构建请求参数
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	params := map[string]string{
		"app_id":     p.appID,
		"method":     "alipay.system.oauth.token",
		"format":     "JSON",
		"charset":    "utf-8",
		"sign_type":  "RSA2",
		"timestamp":  timestamp,
		"version":    "1.0",
		"grant_type": "authorization_code",
		"code":       code,
	}

	// 构建签名字符串
	signContent := buildSignContent(params)
	logger.Debugf("[Alipay] 待签名字符串: %s", signContent)
	sign, err := signWithRSA2(p.privateKey, signContent)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://openapi.alipay.com/gateway.do", strings.NewReader(form.Encode()))
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[Alipay] close response body failed: %v", err)
		}
	}()

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
		subMsg := gjson.Get(bodyStr, "error_response.sub_msg").String()
		logger.Errorf("[Alipay] 登录失败 - Code: %s, Msg: %s, SubMsg: %s", errorCode, errorMsg, subMsg)
		return nil, fmt.Errorf("登录失败: %s - %s", errorMsg, subMsg)
	}

	// 验证响应签名
	if p.publicKey != nil {
		respSign := gjson.Get(bodyStr, "sign").String()
		if respSign != "" {
			responseNode := gjson.Get(bodyStr, "alipay_system_oauth_token_response")
			if responseNode.Exists() {
				responseRaw := responseNode.Raw
				err = verifySign(p.publicKey, responseRaw, respSign)
				if err != nil {
					logger.Errorf("[Alipay] 响应签名验证失败: %v", err)
					return nil, fmt.Errorf("响应签名验证失败: %w", err)
				}
				logger.Infof("[Alipay] 响应签名验证成功")
			}
		}
	}

	// 解析成功响应
	responseNode := gjson.Get(bodyStr, "alipay_system_oauth_token_response")
	if !responseNode.Exists() {
		logger.Errorf("[Alipay] 响应中缺少 alipay_system_oauth_token_response")
		return nil, errors.New("响应中缺少 alipay_system_oauth_token_response")
	}

	// 提取用户ID（使用 open_id 字段）
	userID := gjson.Get(bodyStr, "alipay_system_oauth_token_response.open_id").String()
	if userID == "" {
		logger.Errorf("[Alipay] 响应中缺少 open_id 字段")
		return nil, errors.New("响应中缺少 open_id 字段")
	}

	logger.Infof("[Alipay] 登录成功 - UserID: %s", userID)

	return &idp.ExchangeResult{
		ProviderID: userID,
		RawData:    fmt.Sprintf(`{"openid":"%s"}`, userID),
	}, nil
}

// GetPhoneNumber 获取支付宝手机号
func (*Provider) GetPhoneNumber(ctx context.Context, code string) (string, error) {
	logger.Warnf("[Alipay] 支付宝获取手机号暂未实现")
	return "", errors.New("支付宝获取手机号暂未实现")
}

// ==================== 辅助函数 ====================

// parsePrivateKey 解析 RSA 私钥（支持 PEM 和 DER Base64 格式）
func parsePrivateKey(privateKeyData string) (*rsa.PrivateKey, error) {
	var keyBytes []byte
	var err error

	// 尝试解析为 PEM 格式
	block, _ := pem.Decode([]byte(privateKeyData))
	if block != nil {
		keyBytes = block.Bytes
	} else {
		// 尝试解析为 DER Base64 格式
		keyBytes, err = base64.StdEncoding.DecodeString(privateKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key (not PEM or Base64): %w", err)
		}
	}

	// 尝试 PKCS8 格式
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err == nil {
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return priv, nil
	}

	// 尝试 PKCS1 格式
	priv, err := x509.ParsePKCS1PrivateKey(keyBytes)
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
		keyBytes = block.Bytes
	} else {
		// 尝试解析为 DER Base64 格式
		keyBytes, err = base64.StdEncoding.DecodeString(publicKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key (not PEM or Base64): %w", err)
		}
	}

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
func buildSignContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	items := make([]string, 0, len(keys))
	for _, k := range keys {
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
