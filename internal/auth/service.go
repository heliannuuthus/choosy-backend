package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

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

// TtCode2Session 调用抖音 code2session 接口
func (s *Service) TtCode2Session(code string) (*TtCode2SessionResponse, error) {
	appid := config.GetString("idps.tt.appid")
	secret := config.GetString("idps.tt.secret")
	if appid == "" || secret == "" {
		return nil, errors.New("抖音小程序 IdP 未配置")
	}

	logger.Infof("[Auth] 抖音登录请求 - Code: %s...", code[:min(len(code), 10)])

	params := url.Values{}
	params.Set("appid", appid)
	params.Set("secret", secret)
	params.Set("code", code)

	reqURL := "https://developer.toutiao.com/api/apps/v2/jscode2session?" + params.Encode()

	resp, err := http.Get(reqURL)
	if err != nil {
		logger.Errorf("[Auth] 请求抖音接口失败: %v", err)
		return nil, fmt.Errorf("请求抖音接口失败: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrNo   int    `json:"err_no"`
		ErrTips string `json:"err_tips"`
		Data    struct {
			OpenID     string `json:"openid"`
			SessionKey string `json:"session_key"`
			UnionID    string `json:"unionid,omitempty"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Errorf("[Auth] 解析抖音响应失败: %v", err)
		return nil, fmt.Errorf("解析抖音响应失败: %w", err)
	}

	if result.ErrNo != 0 {
		logger.Errorf("[Auth] 抖音登录失败 - ErrNo: %d, ErrTips: %s", result.ErrNo, result.ErrTips)
		return nil, fmt.Errorf("抖音登录失败: %s", result.ErrTips)
	}

	unionID := "(无)"
	if result.Data.UnionID != "" {
		unionID = result.Data.UnionID
	}
	logger.Infof("[Auth] 抖音登录成功 - T_OpenID: %s, UnionID: %s", result.Data.OpenID, unionID)

	return &TtCode2SessionResponse{
		OpenID:     result.Data.OpenID,
		SessionKey: result.Data.SessionKey,
		UnionID:    result.Data.UnionID,
	}, nil
}

// GenerateTokenFromTt 生成 token（抖音小程序登录）
func (s *Service) GenerateTokenFromTt(ttResult *TtCode2SessionResponse, nickname, avatar string) (*TokenPair, error) {
	params := &LoginParams{
		IDP:      IDPDouyinMP,
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
