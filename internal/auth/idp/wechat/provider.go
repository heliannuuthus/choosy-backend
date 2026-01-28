package wechat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/heliannuuthus/helios/internal/auth/idp"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Provider 微信小程序 Provider
type Provider struct {
	appID     string
	appSecret string
}

// NewProvider 创建微信 Provider
func NewProvider() *Provider {
	return &Provider{
		appID:     config.GetString("idps.wxmp.appid"),
		appSecret: config.GetString("idps.wxmp.secret"),
	}
}

// Type 返回 IDP 类型
func (p *Provider) Type() string {
	return idp.TypeWechatMP
}

// Exchange 用 code 换取用户信息
func (p *Provider) Exchange(ctx context.Context, code string) (*idp.ExchangeResult, error) {
	if p.appID == "" || p.appSecret == "" {
		return nil, errors.New("微信小程序 IdP 未配置")
	}

	logger.Infof("[Wechat] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	params := url.Values{}
	params.Set("appid", p.appID)
	params.Set("secret", p.appSecret)
	params.Set("js_code", code)
	params.Set("grant_type", "authorization_code")

	reqURL := "https://api.weixin.qq.com/sns/jscode2session?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[Wechat] 请求接口失败: %v", err)
		return nil, fmt.Errorf("请求接口失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[WeChat] close response body failed: %v", err)
		}
	}()

	var result code2SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Errorf("[Wechat] 解析响应失败: %v", err)
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if result.ErrCode != 0 {
		logger.Errorf("[Wechat] 登录失败 - ErrCode: %d, ErrMsg: %s", result.ErrCode, result.ErrMsg)
		return nil, fmt.Errorf("登录失败: %s", result.ErrMsg)
	}

	unionID := "(无)"
	if result.UnionID != "" {
		unionID = result.UnionID
	}
	logger.Infof("[Wechat] 登录成功 - OpenID: %s, UnionID: %s", result.OpenID, unionID)

	return &idp.ExchangeResult{
		ProviderID: result.OpenID,
		UnionID:    result.UnionID,
		RawData:    fmt.Sprintf(`{"openid":"%s","unionid":"%s"}`, result.OpenID, result.UnionID),
	}, nil
}

// GetPhoneNumber 获取微信手机号
func (p *Provider) GetPhoneNumber(ctx context.Context, code string) (string, error) {
	accessToken, err := p.getAccessToken(ctx)
	if err != nil {
		return "", err
	}

	reqURL := fmt.Sprintf("https://api.weixin.qq.com/wxa/business/getuserphonenumber?access_token=%s", accessToken)

	body := fmt.Sprintf(`{"code":"%s"}`, code)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[Wechat] 请求获取手机号接口失败: %v", err)
		return "", fmt.Errorf("请求微信接口失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[WeChat] close response body failed: %v", err)
		}
	}()

	var result phoneNumberResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Errorf("[Wechat] 解析手机号响应失败: %v", err)
		return "", fmt.Errorf("解析微信响应失败: %w", err)
	}

	if result.ErrCode != 0 {
		logger.Errorf("[Wechat] 获取手机号失败 - ErrCode: %d, ErrMsg: %s", result.ErrCode, result.ErrMsg)
		return "", fmt.Errorf("微信获取手机号失败: %s", result.ErrMsg)
	}

	phone := result.PhoneInfo.PurePhoneNumber
	if phone == "" {
		phone = result.PhoneInfo.PhoneNumber
	}

	logger.Infof("[Wechat] 获取手机号成功 - Phone: %s***%s", phone[:3], phone[len(phone)-4:])
	return phone, nil
}

// getAccessToken 获取微信 access_token
func (p *Provider) getAccessToken(ctx context.Context) (string, error) {
	if p.appID == "" || p.appSecret == "" {
		return "", errors.New("微信小程序配置缺失")
	}

	reqURL := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s", p.appID, p.appSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求微信 access_token 失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[WeChat] close response body failed: %v", err)
		}
	}()

	var result accessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析微信 access_token 响应失败: %w", err)
	}

	if result.ErrCode != 0 {
		return "", fmt.Errorf("获取微信 access_token 失败: %s", result.ErrMsg)
	}

	return result.AccessToken, nil
}

// 内部响应结构
type code2SessionResponse struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid,omitempty"`
	ErrCode    int    `json:"errcode,omitempty"`
	ErrMsg     string `json:"errmsg,omitempty"`
}

type phoneNumberResponse struct {
	ErrCode   int    `json:"errcode"`
	ErrMsg    string `json:"errmsg"`
	PhoneInfo struct {
		PhoneNumber     string `json:"phoneNumber"`
		PurePhoneNumber string `json:"purePhoneNumber"`
		CountryCode     string `json:"countryCode"`
	} `json:"phone_info"`
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
}
