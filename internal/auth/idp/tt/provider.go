package tt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/heliannuuthus/helios/internal/auth/idp"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Provider 抖音小程序 Provider
type Provider struct {
	appID     string
	appSecret string
}

// NewProvider 创建抖音 Provider
func NewProvider() *Provider {
	return &Provider{
		appID:     config.GetString("idps.tt.appid"),
		appSecret: config.GetString("idps.tt.secret"),
	}
}

// Type 返回 IDP 类型
func (p *Provider) Type() string {
	return idp.TypeTTMP
}

// Exchange 用 code 换取用户信息
func (p *Provider) Exchange(ctx context.Context, code string) (*idp.ExchangeResult, error) {
	if p.appID == "" || p.appSecret == "" {
		return nil, errors.New("TT 小程序 IdP 未配置")
	}

	logger.Infof("[TT] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 抖音 API 使用 POST 请求，body 为 JSON
	reqBody := map[string]string{
		"appid":  p.appID,
		"secret": p.appSecret,
		"code":   code,
	}
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		logger.Errorf("[TT] 构建请求体失败: %v", err)
		return nil, fmt.Errorf("构建请求体失败: %w", err)
	}

	reqURL := "https://developer.toutiao.com/api/apps/v2/jscode2session"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		logger.Errorf("[TT] 创建请求失败: %v", err)
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[TT] 请求接口失败: %v", err)
		return nil, fmt.Errorf("请求接口失败: %w", err)
	}
	defer resp.Body.Close()

	// 先检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Warnf("[TT] read response body failed: %v", err)
		}
		logger.Errorf("[TT] API 返回非 200 状态码: %d, 响应: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("API 请求失败: HTTP %d", resp.StatusCode)
	}

	// 读取响应体
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("[TT] 读取响应失败: %v", err)
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	logger.Infof("[TT] API 原始响应: %s", string(bodyBytes))

	// 使用 gjson 快速检查错误码
	errNo := gjson.GetBytes(bodyBytes, "err_no").Int()
	errTips := gjson.GetBytes(bodyBytes, "err_tips").String()

	// 如果存在错误，直接返回
	if errNo != 0 {
		logger.Errorf("[TT] 登录失败 - ErrNo: %d, ErrTips: %s", errNo, errTips)
		return nil, fmt.Errorf("登录失败: %s", errTips)
	}

	// 检查 data 字段是否存在且不为 null
	dataRaw := gjson.GetBytes(bodyBytes, "data")
	if !dataRaw.Exists() || dataRaw.Raw == "null" {
		logger.Errorf("[TT] 响应 data 字段为空或 null")
		return nil, errors.New("响应 data 字段为空")
	}

	// 解析 data 字段
	openID := gjson.GetBytes(bodyBytes, "data.openid").String()
	unionID := gjson.GetBytes(bodyBytes, "data.unionid").String()

	if openID == "" {
		logger.Errorf("[TT] data 中缺少 openid")
		return nil, errors.New("data 中缺少 openid")
	}

	unionIDLog := "(无)"
	if unionID != "" {
		unionIDLog = unionID
	}
	logger.Infof("[TT] 登录成功 - OpenID: %s, UnionID: %s", openID, unionIDLog)

	return &idp.ExchangeResult{
		ProviderID: openID,
		UnionID:    unionID,
		RawData:    fmt.Sprintf(`{"openid":"%s","unionid":"%s"}`, openID, unionID),
	}, nil
}

// GetPhoneNumber 获取抖音手机号
func (p *Provider) GetPhoneNumber(ctx context.Context, code string) (string, error) {
	if p.appID == "" || p.appSecret == "" {
		return "", errors.New("TT 小程序配置缺失")
	}

	accessToken, err := p.getAccessToken(ctx)
	if err != nil {
		return "", err
	}

	reqURL := fmt.Sprintf("https://developer.toutiao.com/api/apps/v2/user/get_phone_number?access_token=%s", accessToken)

	body := fmt.Sprintf(`{"code":"%s"}`, code)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[TT] 请求获取手机号接口失败: %v", err)
		return "", fmt.Errorf("请求 TT 接口失败: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrNo   int    `json:"err_no"`
		ErrTips string `json:"err_tips"`
		Data    struct {
			PhoneNumber string `json:"phone_number"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Errorf("[TT] 解析手机号响应失败: %v", err)
		return "", fmt.Errorf("解析 TT 响应失败: %w", err)
	}

	if result.ErrNo != 0 {
		logger.Errorf("[TT] 获取手机号失败 - ErrNo: %d, ErrTips: %s", result.ErrNo, result.ErrTips)
		return "", fmt.Errorf("TT 获取手机号失败: %s", result.ErrTips)
	}

	phone := result.Data.PhoneNumber
	if phone == "" {
		return "", errors.New("TT 返回的手机号为空")
	}

	logger.Infof("[TT] 获取手机号成功 - Phone: %s***%s", phone[:3], phone[len(phone)-4:])
	return phone, nil
}

// getAccessToken 获取 TT access_token
func (p *Provider) getAccessToken(ctx context.Context) (string, error) {
	if p.appID == "" || p.appSecret == "" {
		return "", errors.New("TT 小程序配置缺失")
	}

	reqURL := fmt.Sprintf("https://developer.toutiao.com/api/apps/v2/token?appid=%s&secret=%s&grant_type=client_credential", p.appID, p.appSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求 TT access_token 失败: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrNo   int    `json:"err_no"`
		ErrTips string `json:"err_tips"`
		Data    struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析 TT access_token 响应失败: %w", err)
	}

	if result.ErrNo != 0 {
		return "", fmt.Errorf("获取 TT access_token 失败: %s", result.ErrTips)
	}

	return result.Data.AccessToken, nil
}
