package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"choosy-backend/internal/config"

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

	params := url.Values{}
	params.Set("appid", appid)
	params.Set("secret", secret)
	params.Set("js_code", code)
	params.Set("grant_type", "authorization_code")

	reqURL := "https://api.weixin.qq.com/sns/jscode2session?" + params.Encode()

	resp, err := http.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("请求微信接口失败: %w", err)
	}
	defer resp.Body.Close()

	var result WxCode2SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析微信响应失败: %w", err)
	}

	if result.ErrCode != 0 {
		return nil, fmt.Errorf("微信登录失败: %s", result.ErrMsg)
	}

	return &result, nil
}

// GenerateToken 生成 token
func (s *Service) GenerateToken(openid, nickname, avatar string) (*TokenPair, error) {
	return GenerateTokenPair(s.db, openid, nickname, avatar)
}

// VerifyToken 验证 access_token
func (s *Service) VerifyToken(token string) (*Identity, error) {
	return VerifyAccessToken(token)
}

// RefreshToken 刷新 token
func (s *Service) RefreshToken(refreshToken string) (*TokenPair, error) {
	return RefreshTokens(s.db, refreshToken)
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

