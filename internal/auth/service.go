package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/tidwall/gjson"

	"choosy-backend/internal/config"
	"choosy-backend/internal/logger"

	"gorm.io/gorm"
)

// Service 认证服务
type Service struct {
	db *gorm.DB
}

// NewService 创建认证服务
func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// WxCode2Session 调用微信 code2session 接口
func (s *Service) WxCode2Session(code string) (*WxCode2SessionResponse, error) {
	appid := config.GetString("idps.wxmp.appid")
	secret := config.GetString("idps.wxmp.secret")
	if appid == "" || secret == "" {
		return nil, errors.New("微信小程序 IdP 未配置")
	}

	logger.Infof("[Auth] 微信登录请求 - Code: %s...", code[:min(len(code), 10)])

	params := url.Values{}
	params.Set("appid", appid)
	params.Set("secret", secret)
	params.Set("js_code", code)
	params.Set("grant_type", "authorization_code")

	reqURL := "https://api.weixin.qq.com/sns/jscode2session?" + params.Encode()

	resp, err := http.Get(reqURL)
	if err != nil {
		logger.Errorf("[Auth] 请求微信接口失败: %v", err)
		return nil, fmt.Errorf("请求微信接口失败: %w", err)
	}
	defer resp.Body.Close()

	var result WxCode2SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Errorf("[Auth] 解析微信响应失败: %v", err)
		return nil, fmt.Errorf("解析微信响应失败: %w", err)
	}

	if result.ErrCode != 0 {
		logger.Errorf("[Auth] 微信登录失败 - ErrCode: %d, ErrMsg: %s", result.ErrCode, result.ErrMsg)
		return nil, fmt.Errorf("微信登录失败: %s", result.ErrMsg)
	}

	unionID := "(无)"
	if result.UnionID != "" {
		unionID = result.UnionID
	}
	logger.Infof("[Auth] 微信登录成功 - T_OpenID: %s, UnionID: %s", result.OpenID, unionID)

	return &result, nil
}

// GenerateToken 生成 token（微信小程序登录）
func (s *Service) GenerateToken(wxResult *WxCode2SessionResponse, nickname, avatar string) (*TokenPair, error) {
	params := &LoginParams{
		IDP:      IDPWechatMP,
		TOpenID:  wxResult.OpenID,
		UnionID:  wxResult.UnionID,
		Nickname: nickname,
		Avatar:   avatar,
	}
	return GenerateTokenPair(s.db, params)
}

// TtCode2Session 调用 TT code2session 接口
func (s *Service) TtCode2Session(code string) (*TtCode2SessionResponse, error) {
	appid := config.GetString("idps.tt.appid")
	secret := config.GetString("idps.tt.secret")
	if appid == "" || secret == "" {
		return nil, errors.New("TT 小程序 IdP 未配置")
	}

	logger.Infof("[Auth] TT 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 抖音 API 使用 POST 请求，body 为 JSON
	reqBody := map[string]string{
		"appid":  appid,
		"secret": secret,
		"code":   code,
	}
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		logger.Errorf("[Auth] 构建 TT 请求体失败: %v", err)
		return nil, fmt.Errorf("构建 TT 请求体失败: %w", err)
	}

	reqURL := "https://developer.toutiao.com/api/apps/v2/jscode2session"

	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		logger.Errorf("[Auth] 创建 TT 请求失败: %v", err)
		return nil, fmt.Errorf("创建 TT 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[Auth] 请求 TT 接口失败: %v", err)
		return nil, fmt.Errorf("请求 TT 接口失败: %w", err)
	}
	defer resp.Body.Close()

	// 先检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logger.Errorf("[Auth] TT API 返回非 200 状态码: %d, 响应: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("TT API 请求失败: HTTP %d", resp.StatusCode)
	}

	// 读取响应体
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("[Auth] 读取 TT 响应失败: %v", err)
		return nil, fmt.Errorf("读取 TT 响应失败: %w", err)
	}

	logger.Infof("[Auth] TT API 原始响应: %s", string(bodyBytes))

	// 使用 gjson 快速检查错误码
	errNo := gjson.GetBytes(bodyBytes, "err_no").Int()
	errTips := gjson.GetBytes(bodyBytes, "err_tips").String()

	// 如果存在错误，直接返回
	if errNo != 0 {
		logger.Errorf("[Auth] TT 登录失败 - ErrNo: %d, ErrTips: %s", errNo, errTips)
		return nil, fmt.Errorf("TT 登录失败: %s", errTips)
	}

	// 检查 data 字段是否存在且不为 null
	dataRaw := gjson.GetBytes(bodyBytes, "data")
	if !dataRaw.Exists() || dataRaw.Raw == "null" {
		logger.Errorf("[Auth] TT 响应 data 字段为空或 null")
		return nil, fmt.Errorf("TT 登录失败: 响应数据为空")
	}

	// 使用 gjson 提取 data 字段中的值
	openID := gjson.GetBytes(bodyBytes, "data.openid").String()
	sessionKey := gjson.GetBytes(bodyBytes, "data.session_key").String()
	unionID := gjson.GetBytes(bodyBytes, "data.unionid").String()

	// 验证必要字段
	if openID == "" || sessionKey == "" {
		logger.Errorf("[Auth] TT 响应缺少必要字段 - openid: %s, session_key: %s", openID, sessionKey)
		return nil, fmt.Errorf("TT 登录失败: 响应数据不完整")
	}

	unionIDDisplay := "(无)"
	if unionID != "" {
		unionIDDisplay = unionID
	}
	logger.Infof("[Auth] TT 登录成功 - T_OpenID: %s, UnionID: %s", openID, unionIDDisplay)

	return &TtCode2SessionResponse{
		OpenID:     openID,
		SessionKey: sessionKey,
		UnionID:    unionID,
	}, nil
}

// GenerateTokenFromTt 生成 token（TT 小程序登录）
func (s *Service) GenerateTokenFromTt(ttResult *TtCode2SessionResponse, nickname, avatar string) (*TokenPair, error) {
	params := &LoginParams{
		IDP:      IDPTTMP,
		TOpenID:  ttResult.OpenID,
		UnionID:  ttResult.UnionID,
		Nickname: nickname,
		Avatar:   avatar,
	}
	return GenerateTokenPair(s.db, params)
}

// AlipayCode2Session 调用支付宝 code2session 接口
func (s *Service) AlipayCode2Session(code string) (*AlipayCode2SessionResponse, error) {
	appid := config.GetString("idps.alipay.appid")
	secret := config.GetString("idps.alipay.secret")
	if appid == "" || secret == "" {
		return nil, errors.New("支付宝小程序 IdP 未配置")
	}

	logger.Infof("[Auth] 支付宝登录请求 - Code: %s...", code[:min(len(code), 10)])

	// TODO: 支付宝需要签名，这里简化处理，实际需要实现签名逻辑
	// 支付宝的 code2session 接口比较复杂，需要 RSA 签名
	// 需要实现以下步骤：
	// 1. 构建请求参数（app_id, method, format, charset, sign_type, timestamp, version, grant_type, code）
	// 2. 使用 RSA2 私钥对参数进行签名
	// 3. POST 请求到 https://openapi.alipay.com/gateway.do
	// 4. 解析响应获取 openid 和 session_key

	logger.Warnf("[Auth] 支付宝登录暂未完全实现，需要 RSA 签名")
	return nil, fmt.Errorf("支付宝登录暂未完全实现，需要配置 RSA 密钥和实现签名逻辑")
}

// GenerateTokenFromAlipay 生成 token（支付宝小程序登录）
func (s *Service) GenerateTokenFromAlipay(alipayResult *AlipayCode2SessionResponse, nickname, avatar string) (*TokenPair, error) {
	params := &LoginParams{
		IDP:      IDPAlipayMP,
		TOpenID:  alipayResult.OpenID,
		UnionID:  alipayResult.UnionID,
		Nickname: nickname,
		Avatar:   avatar,
	}
	return GenerateTokenPair(s.db, params)
}

// VerifyToken 验证 access_token
func (s *Service) VerifyToken(token string) (*Identity, error) {
	return VerifyAccessToken(token)
}

// RefreshToken 刷新 token
func (s *Service) RefreshToken(refreshToken string, idp string) (*TokenPair, error) {
	return RefreshTokens(s.db, refreshToken, idp)
}

// RevokeToken 撤销 refresh_token
func (s *Service) RevokeToken(refreshToken string) bool {
	return RevokeRefreshToken(s.db, refreshToken)
}

// RevokeAllTokens 撤销用户所有 refresh_token
func (s *Service) RevokeAllTokens(openid string) int64 {
	return RevokeAllRefreshTokens(s.db, openid)
}

// GetCurrentUser 从 Authorization header 获取当前用户
func GetCurrentUser(authorization string) (*Identity, error) {
	if authorization == "" {
		return nil, errors.New("未提供认证信息")
	}

	token := authorization
	if len(authorization) > 7 && authorization[:7] == "Bearer " {
		token = authorization[7:]
	}

	return VerifyAccessToken(token)
}
