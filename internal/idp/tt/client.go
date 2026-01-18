package tt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tidwall/gjson"

	"zwei-backend/internal/config"
	"zwei-backend/internal/logger"
)

// Code2SessionResponse TT code2session 响应
type Code2SessionResponse struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid,omitempty"`
	ErrCode    int    `json:"errcode,omitempty"`
	ErrMsg     string `json:"errmsg,omitempty"`
}

// Client 抖音客户端
type Client struct{}

// NewClient 创建抖音客户端
func NewClient() *Client {
	return &Client{}
}

// Code2Session 调用 TT code2session 接口
func (c *Client) Code2Session(code string) (*Code2SessionResponse, error) {
	appid := config.GetString("idps.tt.appid")
	secret := config.GetString("idps.tt.secret")
	if appid == "" || secret == "" {
		return nil, errors.New("TT 小程序 IdP 未配置")
	}

	logger.Infof("[TT] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 抖音 API 使用 POST 请求，body 为 JSON
	reqBody := map[string]string{
		"appid":  appid,
		"secret": secret,
		"code":   code,
	}
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		logger.Errorf("[TT] 构建请求体失败: %v", err)
		return nil, fmt.Errorf("构建请求体失败: %w", err)
	}

	reqURL := "https://developer.toutiao.com/api/apps/v2/jscode2session"

	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(reqBodyBytes))
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
		bodyBytes, _ := io.ReadAll(resp.Body)
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
	var data struct {
		SessionKey string `json:"session_key"`
		OpenID     string `json:"openid"`
		UnionID    string `json:"unionid,omitempty"`
	}

	if err := json.Unmarshal([]byte(dataRaw.Raw), &data); err != nil {
		logger.Errorf("[TT] 解析 data 字段失败: %v", err)
		return nil, fmt.Errorf("解析 data 字段失败: %w", err)
	}

	if data.OpenID == "" {
		logger.Errorf("[TT] data 中缺少 openid")
		return nil, errors.New("data 中缺少 openid")
	}

	unionID := "(无)"
	if data.UnionID != "" {
		unionID = data.UnionID
	}
	logger.Infof("[TT] 登录成功 - OpenID: %s, UnionID: %s", data.OpenID, unionID)

	return &Code2SessionResponse{
		OpenID:     data.OpenID,
		SessionKey: data.SessionKey,
		UnionID:    data.UnionID,
	}, nil
}

// GetPhoneNumber 获取抖音手机号
func (c *Client) GetPhoneNumber(code string) (string, error) {
	appid := config.GetString("idps.tt.appid")
	secret := config.GetString("idps.tt.secret")
	if appid == "" || secret == "" {
		return "", errors.New("TT 小程序配置缺失")
	}

	accessToken, err := c.getAccessToken()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://developer.toutiao.com/api/apps/v2/user/get_phone_number?access_token=%s", accessToken)

	body := fmt.Sprintf(`{"code":"%s"}`, code)
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
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
func (c *Client) getAccessToken() (string, error) {
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
