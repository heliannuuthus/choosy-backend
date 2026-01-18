package wechat

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"zwei-backend/internal/config"
	"zwei-backend/internal/logger"
)

// Code2SessionResponse 微信 code2session 响应
type Code2SessionResponse struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid,omitempty"`
	ErrCode    int    `json:"errcode,omitempty"`
	ErrMsg     string `json:"errmsg,omitempty"`
}

// Client 微信客户端
type Client struct{}

// NewClient 创建微信客户端
func NewClient() *Client {
	return &Client{}
}

// Code2Session 调用微信 code2session 接口
func (c *Client) Code2Session(code string) (*Code2SessionResponse, error) {
	appid := config.GetString("idps.wxmp.appid")
	secret := config.GetString("idps.wxmp.secret")
	if appid == "" || secret == "" {
		return nil, errors.New("微信小程序 IdP 未配置")
	}

	logger.Infof("[Wechat] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	params := url.Values{}
	params.Set("appid", appid)
	params.Set("secret", secret)
	params.Set("js_code", code)
	params.Set("grant_type", "authorization_code")

	reqURL := "https://api.weixin.qq.com/sns/jscode2session?" + params.Encode()

	resp, err := http.Get(reqURL)
	if err != nil {
		logger.Errorf("[Wechat] 请求接口失败: %v", err)
		return nil, fmt.Errorf("请求接口失败: %w", err)
	}
	defer resp.Body.Close()

	var result Code2SessionResponse
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

	return &result, nil
}

// GetPhoneNumber 获取微信手机号
func (c *Client) GetPhoneNumber(code string) (string, error) {
	accessToken, err := c.getAccessToken()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.weixin.qq.com/wxa/business/getuserphonenumber?access_token=%s", accessToken)

	body := fmt.Sprintf(`{"code":"%s"}`, code)
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		logger.Errorf("[Wechat] 请求获取手机号接口失败: %v", err)
		return "", fmt.Errorf("请求微信接口失败: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrCode   int    `json:"errcode"`
		ErrMsg    string `json:"errmsg"`
		PhoneInfo struct {
			PhoneNumber     string `json:"phoneNumber"`
			PurePhoneNumber string `json:"purePhoneNumber"`
			CountryCode     string `json:"countryCode"`
		} `json:"phone_info"`
	}
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
func (c *Client) getAccessToken() (string, error) {
	appid := config.GetString("idps.wxmp.appid")
	secret := config.GetString("idps.wxmp.secret")
	if appid == "" || secret == "" {
		return "", errors.New("微信小程序配置缺失")
	}

	url := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s", appid, secret)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("请求微信 access_token 失败: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析微信 access_token 响应失败: %w", err)
	}

	if result.ErrCode != 0 {
		return "", fmt.Errorf("获取微信 access_token 失败: %s", result.ErrMsg)
	}

	return result.AccessToken, nil
}
