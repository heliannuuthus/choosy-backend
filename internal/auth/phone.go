package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"choosy-backend/internal/config"
	"choosy-backend/internal/logger"
)

// PhoneProvider 手机号获取接口
type PhoneProvider interface {
	GetPhoneNumber(code string) (string, error)
}

// GetPhoneProvider 根据 idp 获取对应的 PhoneProvider
func GetPhoneProvider(idp string) (PhoneProvider, error) {
	switch idp {
	case IDPWechatMP:
		return &WechatPhoneProvider{}, nil
	case IDPTTMP:
		return &TTPhoneProvider{}, nil
	case IDPAlipayMP:
		return &AlipayPhoneProvider{}, nil
	default:
		return nil, fmt.Errorf("不支持的平台: %s", idp)
	}
}

// ParseIDPFromAudience 从 aud 解析 idp
// aud 格式: issuer:provider:namespace，如 choosy:wechat:mp
func ParseIDPFromAudience(aud string) string {
	parts := strings.SplitN(aud, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1] // 返回 wechat:mp
}

// ==================== 微信实现 ====================

type WechatPhoneProvider struct{}

type wxPhoneResponse struct {
	ErrCode   int    `json:"errcode"`
	ErrMsg    string `json:"errmsg"`
	PhoneInfo struct {
		PhoneNumber     string `json:"phoneNumber"`
		PurePhoneNumber string `json:"purePhoneNumber"`
		CountryCode     string `json:"countryCode"`
	} `json:"phone_info"`
}

func (p *WechatPhoneProvider) GetPhoneNumber(code string) (string, error) {
	accessToken, err := getWxAccessToken()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.weixin.qq.com/wxa/business/getuserphonenumber?access_token=%s", accessToken)

	body := fmt.Sprintf(`{"code":"%s"}`, code)
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		logger.Errorf("[Auth] 请求微信获取手机号接口失败: %v", err)
		return "", fmt.Errorf("请求微信接口失败: %w", err)
	}
	defer resp.Body.Close()

	var result wxPhoneResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Errorf("[Auth] 解析微信手机号响应失败: %v", err)
		return "", fmt.Errorf("解析微信响应失败: %w", err)
	}

	if result.ErrCode != 0 {
		logger.Errorf("[Auth] 微信获取手机号失败 - ErrCode: %d, ErrMsg: %s", result.ErrCode, result.ErrMsg)
		return "", fmt.Errorf("微信获取手机号失败: %s", result.ErrMsg)
	}

	phone := result.PhoneInfo.PurePhoneNumber
	if phone == "" {
		phone = result.PhoneInfo.PhoneNumber
	}

	logger.Infof("[Auth] 微信获取手机号成功 - Phone: %s***%s", phone[:3], phone[len(phone)-4:])
	return phone, nil
}

// getWxAccessToken 获取微信 access_token
// TODO: 应该缓存，避免频繁请求
func getWxAccessToken() (string, error) {
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

// ==================== TT 实现 ====================

type TTPhoneProvider struct{}

type ttPhoneResponse struct {
	ErrNo   int    `json:"err_no"`
	ErrTips string `json:"err_tips"`
	Data    struct {
		PhoneNumber string `json:"phone_number"`
	} `json:"data"`
}

func (p *TTPhoneProvider) GetPhoneNumber(code string) (string, error) {
	appid := config.GetString("idps.tt.appid")
	secret := config.GetString("idps.tt.secret")
	if appid == "" || secret == "" {
		return "", errors.New("TT 小程序配置缺失")
	}

	// 获取 access_token
	accessToken, err := getTtAccessToken()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://developer.toutiao.com/api/apps/v2/user/get_phone_number?access_token=%s", accessToken)

	body := fmt.Sprintf(`{"code":"%s"}`, code)
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		logger.Errorf("[Auth] 请求 TT 获取手机号接口失败: %v", err)
		return "", fmt.Errorf("请求 TT 接口失败: %w", err)
	}
	defer resp.Body.Close()

	var result ttPhoneResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Errorf("[Auth] 解析 TT 手机号响应失败: %v", err)
		return "", fmt.Errorf("解析 TT 响应失败: %w", err)
	}

	if result.ErrNo != 0 {
		logger.Errorf("[Auth] TT 获取手机号失败 - ErrNo: %d, ErrTips: %s", result.ErrNo, result.ErrTips)
		return "", fmt.Errorf("TT 获取手机号失败: %s", result.ErrTips)
	}

	phone := result.Data.PhoneNumber
	if phone == "" {
		return "", errors.New("TT 返回的手机号为空")
	}

	logger.Infof("[Auth] TT 获取手机号成功 - Phone: %s***%s", phone[:3], phone[len(phone)-4:])
	return phone, nil
}

// getTtAccessToken 获取 TT access_token
func getTtAccessToken() (string, error) {
	appid := config.GetString("idps.tt.appid")
	secret := config.GetString("idps.tt.secret")
	if appid == "" || secret == "" {
		return "", errors.New("TT 小程序配置缺失")
	}

	url := fmt.Sprintf("https://developer.toutiao.com/api/apps/v2/token?appid=%s&secret=%s&grant_type=client_credential", appid, secret)

	resp, err := http.Get(url)
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

// ==================== 支付宝实现 ====================

type AlipayPhoneProvider struct{}

func (p *AlipayPhoneProvider) GetPhoneNumber(code string) (string, error) {
	// 支付宝获取手机号需要 RSA 签名，比较复杂
	// 这里先返回未实现错误，后续可以完善
	logger.Warnf("[Auth] 支付宝获取手机号暂未完全实现，需要 RSA 签名")
	return "", errors.New("支付宝获取手机号暂未完全实现，需要配置 RSA 密钥和实现签名逻辑")
}
