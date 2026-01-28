package authorize

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/heliannuuthus/helios/internal/auth/cache"
	"github.com/heliannuuthus/helios/internal/auth/token"
	"github.com/heliannuuthus/helios/internal/auth/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/kms"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// 错误定义
var (
	ErrInvalidGrant     = errors.New("invalid grant")
	ErrInvalidCode      = errors.New("invalid authorization code")
	ErrCodeExpired      = errors.New("authorization code expired")
	ErrCodeUsed         = errors.New("authorization code already used")
	ErrInvalidVerifier  = errors.New("invalid code verifier")
	ErrClientMismatch   = errors.New("client_id mismatch")
	ErrRedirectMismatch = errors.New("redirect_uri mismatch")
	ErrFlowNotFound     = errors.New("auth flow not found")
)

// Service 授权服务
type Service struct {
	cache    *cache.Manager
	tokenSvc *token.Service

	// 配置
	defaultAccessTTL  time.Duration
	defaultRefreshTTL time.Duration
	authCodeTTL       time.Duration
}

// ServiceConfig 服务配置
type ServiceConfig struct {
	Cache    *cache.Manager
	TokenSvc *token.Service

	DefaultAccessTTL  time.Duration
	DefaultRefreshTTL time.Duration
	AuthCodeTTL       time.Duration
}

// NewService 创建授权服务
func NewService(cfg *ServiceConfig) *Service {
	return &Service{
		cache:             cfg.Cache,
		tokenSvc:          cfg.TokenSvc,
		defaultAccessTTL:  defaultDuration(cfg.DefaultAccessTTL, 2*time.Hour),
		defaultRefreshTTL: defaultDuration(cfg.DefaultRefreshTTL, 7*24*time.Hour),
		authCodeTTL:       defaultDuration(cfg.AuthCodeTTL, 5*time.Minute),
	}
}

func defaultDuration(val, def time.Duration) time.Duration {
	if val == 0 {
		return def
	}
	return val
}

// ==================== 授权准备 ====================

// PrepareAuthorization 准备授权
// 计算 scope 交集，更新 AuthFlow.GrantedScopes
func (s *Service) PrepareAuthorization(ctx context.Context, flow *types.AuthFlow) error {
	if flow.User == nil {
		return errors.New("user not set in flow")
	}

	// 1. 获取请求的 scope
	requestedScopes := flow.Request.ParseScopes()

	// 确保包含 openid
	hasOpenID := false
	for _, scope := range requestedScopes {
		if scope == ScopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		requestedScopes = append([]string{ScopeOpenID}, requestedScopes...)
	}

	// 2. 获取 connection 允许的 scope
	connectionConfig := flow.ConnectionMap[flow.Connection]
	if connectionConfig == nil {
		return fmt.Errorf("connection %s not found in flow", flow.Connection)
	}

	allowedScopes := connectionConfig.AllowedScopes
	if len(allowedScopes) == 0 {
		allowedScopes = []string{ScopeOpenID}
	}

	// 3. 计算交集
	grantedScopes := scopeIntersection(requestedScopes, allowedScopes)

	// 4. 检查是否有有效的 scope
	hasValidScope := false
	for _, scope := range grantedScopes {
		if scope != ScopeOpenID {
			hasValidScope = true
			break
		}
	}
	if !hasValidScope && len(grantedScopes) == 1 {
		// 只有 openid，没有其他 scope
		logger.Warnf("[Authorize] 没有有效的 scope - Requested: %v, Allowed: %v", requestedScopes, allowedScopes)
	}

	// 5. 更新 flow
	flow.SetAuthorized(grantedScopes)

	logger.Infof("[Authorize] 准备授权完成 - FlowID: %s, GrantedScopes: %v", flow.ID, grantedScopes)

	return nil
}

// GenerateAuthCode 生成授权码
func (s *Service) GenerateAuthCode(ctx context.Context, flow *types.AuthFlow) (*types.AuthorizationCode, error) {
	now := time.Now()

	code := &types.AuthorizationCode{
		Code:      types.GenerateAuthorizationCode(),
		FlowID:    flow.ID,
		State:     flow.Request.State,
		CreatedAt: now,
		ExpiresAt: now.Add(s.authCodeTTL),
		Used:      false,
	}

	// 保存到缓存（转换为 cache.AuthorizationCode）
	cacheCode := &cache.AuthorizationCode{
		Code:      code.Code,
		FlowID:    code.FlowID,
		State:     code.State,
		CreatedAt: code.CreatedAt,
		ExpiresAt: code.ExpiresAt,
		Used:      code.Used,
	}
	if err := s.cache.SaveAuthCode(ctx, cacheCode); err != nil {
		return nil, fmt.Errorf("save auth code failed: %w", err)
	}

	// 更新 flow 状态
	flow.SetCompleted()

	logger.Infof("[Authorize] 生成授权码 - FlowID: %s, Code: %s...", flow.ID, code.Code[:8])

	return code, nil
}

// ==================== Token 交换 ====================

// ExchangeToken 用授权码换取 Token
func (s *Service) ExchangeToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, req)
	case GrantTypeRefreshToken:
		return s.refreshToken(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported grant type: %s", req.GrantType)
	}
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// 1. 获取授权码
	authCode, err := s.cache.GetAuthCode(ctx, req.Code)
	if err != nil {
		return nil, ErrInvalidCode
	}

	// 2. 获取 AuthFlow
	flowData, err := s.cache.GetAuthFlow(ctx, authCode.FlowID)
	if err != nil {
		return nil, ErrFlowNotFound
	}

	var flow types.AuthFlow
	if err := json.Unmarshal(flowData, &flow); err != nil {
		return nil, fmt.Errorf("unmarshal flow failed: %w", err)
	}

	// 3. 验证 client_id
	if req.ClientID != flow.Request.ClientID {
		return nil, ErrClientMismatch
	}

	// 4. 验证 redirect_uri
	if req.RedirectURI != flow.Request.RedirectURI {
		return nil, ErrRedirectMismatch
	}

	// 5. 验证 PKCE
	if !verifyCodeChallenge(flow.Request.CodeChallengeMethod, flow.Request.CodeChallenge, req.CodeVerifier) {
		return nil, ErrInvalidVerifier
	}

	// 6. 标记授权码已使用
	if err := s.cache.MarkAuthCodeUsed(ctx, req.Code); err != nil {
		logger.Warnf("[Authorize] 标记授权码已使用失败: %v", err)
	}

	// 7. 生成 Token
	return s.generateTokens(ctx, &flow)
}

func (s *Service) refreshToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// 1. 获取 refresh token
	rt, err := s.cache.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, ErrInvalidGrant
	}

	// 2. 验证 client_id
	if req.ClientID != rt.ClientID {
		return nil, ErrClientMismatch
	}

	// 3. 获取用户、应用、服务信息
	user, err := s.cache.GetUser(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	app, err := s.cache.GetApplication(ctx, rt.ClientID)
	if err != nil {
		return nil, fmt.Errorf("application not found: %w", err)
	}

	svc, err := s.cache.GetService(ctx, rt.Audience)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}

	// 4. 生成新的 access token
	tokenResp, err := s.generateAccessToken(ctx, app, svc, user, rt.Scope)
	if err != nil {
		return nil, err
	}

	// 保持 refresh token 不变
	tokenResp.RefreshToken = rt.Token

	return tokenResp, nil
}

// generateTokens 生成 token（用于授权码交换）
func (s *Service) generateTokens(ctx context.Context, flow *types.AuthFlow) (*TokenResponse, error) {
	scope := strings.Join(flow.GrantedScopes, " ")

	// 生成 access token
	tokenResp, err := s.generateAccessToken(ctx, flow.Application, flow.Service, flow.User, scope)
	if err != nil {
		return nil, err
	}

	// 如果 scope 包含 offline_access，生成 refresh token
	if containsScope(flow.GrantedScopes, ScopeOfflineAccess) {
		rt, err := s.createRefreshToken(ctx, flow, scope)
		if err != nil {
			return nil, err
		}
		tokenResp.RefreshToken = rt.Token
	}

	return tokenResp, nil
}

func (s *Service) generateAccessToken(
	ctx context.Context,
	app *models.ApplicationWithKey,
	svc *models.ServiceWithKey,
	user *models.UserWithDecrypted,
	scope string,
) (*TokenResponse, error) {
	// 计算 TTL
	accessTTL := time.Duration(svc.AccessTokenExpiresIn) * time.Second
	if accessTTL == 0 {
		accessTTL = s.defaultAccessTTL
	}

	// 构建用户 Claims
	userClaims := s.buildUserClaims(user, scope)

	// 创建 Access Token
	uat := token.NewUserAccessToken(
		s.tokenSvc.GetIssuerName(),
		app.AppID,
		svc.ServiceID,
		scope,
		accessTTL,
		userClaims,
	)

	accessToken, err := s.tokenSvc.Issue(ctx, uat)
	if err != nil {
		return nil, fmt.Errorf("issue token failed: %w", err)
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTTL.Seconds()),
		Scope:       scope,
	}, nil
}

func (s *Service) createRefreshToken(ctx context.Context, flow *types.AuthFlow, scope string) (*cache.RefreshToken, error) {
	// 计算 TTL
	refreshTTL := time.Duration(flow.Service.RefreshTokenExpiresIn) * time.Second
	if refreshTTL == 0 {
		refreshTTL = s.defaultRefreshTTL
	}

	// 清理旧的 refresh token
	s.cleanupOldRefreshTokens(ctx, flow.User.OpenID, flow.Application.AppID)

	// 创建新的 refresh token
	now := time.Now()
	rt := &cache.RefreshToken{
		Token:     generateRefreshTokenValue(),
		UserID:    flow.User.OpenID,
		ClientID:  flow.Application.AppID,
		Audience:  flow.Service.ServiceID,
		Scope:     scope,
		ExpiresAt: now.Add(refreshTTL),
		CreatedAt: now,
	}

	if err := s.cache.SaveRefreshToken(ctx, rt); err != nil {
		return nil, fmt.Errorf("save refresh token failed: %w", err)
	}

	return rt, nil
}

func (s *Service) cleanupOldRefreshTokens(ctx context.Context, userID, clientID string) {
	maxTokens := config.GetInt("auth.max-refresh-token")
	if maxTokens <= 0 {
		maxTokens = 10
	}

	tokens, err := s.cache.ListUserRefreshTokens(ctx, userID, clientID)
	if err != nil {
		return
	}

	if len(tokens) >= maxTokens {
		for i := maxTokens - 1; i < len(tokens); i++ {
			if err := s.cache.RevokeRefreshToken(ctx, tokens[i].Token); err != nil {
				// 记录错误但不中断流程
				logger.Warnf("revoke refresh token failed: %v", err)
			}
		}
	}
}

func (s *Service) buildUserClaims(user *models.UserWithDecrypted, scope string) *token.Claims {
	claims := &token.Claims{
		OpenID: user.OpenID,
	}

	scopes := parseScopeSet(scope)

	if scopes[ScopeProfile] {
		claims.Nickname = user.Name
		claims.Picture = user.Picture
	}

	if scopes[ScopeEmail] && user.Email != nil {
		claims.Email = *user.Email
	}

	if scopes[ScopePhone] && user.Phone != "" {
		claims.Phone = user.Phone
	}

	return claims
}

// ==================== Token 撤销 ====================

// RevokeToken 撤销 Token
func (s *Service) RevokeToken(ctx context.Context, tokenValue string) error {
	return s.cache.RevokeRefreshToken(ctx, tokenValue)
}

// RevokeAllTokens 撤销用户所有 Token
func (s *Service) RevokeAllTokens(ctx context.Context, userID string) error {
	return s.cache.RevokeUserRefreshTokens(ctx, userID)
}

// ==================== UserInfo ====================

// GetUserInfo 获取用户信息（根据 scope 脱敏）
func (s *Service) GetUserInfo(ctx context.Context, openID, scope string) (*UserInfoResponse, error) {
	user, err := s.cache.GetUser(ctx, openID)
	if err != nil {
		return nil, err
	}

	resp := &UserInfoResponse{
		Sub: user.OpenID,
	}

	scopes := parseScopeSet(scope)

	if scopes[ScopeProfile] {
		resp.Nickname = user.Name
		resp.Picture = user.Picture
	}

	if scopes[ScopeEmail] && user.Email != nil {
		resp.Email = maskEmail(*user.Email)
	}

	if scopes[ScopePhone] && user.Phone != "" {
		resp.Phone = maskPhone(user.Phone)
	}

	return resp, nil
}

// ==================== JWKS ====================

// GetJWKS 获取 JWKS（根据 client_id 返回其所属域的公钥）
func (s *Service) GetJWKS(ctx context.Context, clientID string) (map[string]interface{}, error) {
	// 1. 获取 Application
	app, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	// 2. 获取域信息和公钥
	domain, err := s.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("domain not found: %w", err)
	}

	// 3. 解析签名密钥获取公钥
	signKey, err := jwk.ParseKey(domain.SignKey)
	if err != nil {
		return nil, fmt.Errorf("parse sign key: %w", err)
	}

	publicKey, err := signKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	// 4. 构建 JWKS 响应
	set := jwk.NewSet()
	if err := set.AddKey(publicKey); err != nil {
		return nil, fmt.Errorf("add public key to jwks: %w", err)
	}

	jsonBytes, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("marshal jwks: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, fmt.Errorf("unmarshal jwks: %w", err)
	}

	return result, nil
}

// ==================== 辅助函数 ====================

// verifyCodeChallenge 验证 PKCE
func verifyCodeChallenge(method, challenge, verifier string) bool {
	if verifier == "" {
		return false
	}

	switch method {
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		return computed == challenge
	default:
		return false
	}
}

// scopeIntersection 计算 scope 交集
func scopeIntersection(requested, allowed []string) []string {
	allowedSet := make(map[string]bool)
	for _, s := range allowed {
		allowedSet[s] = true
	}

	var result []string
	for _, s := range requested {
		if allowedSet[s] {
			result = append(result, s)
		}
	}
	return result
}

// containsScope 检查是否包含指定 scope
func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// parseScopeSet 解析 scope 为集合
func parseScopeSet(scope string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		set[s] = true
	}
	return set
}

// generateRefreshTokenValue 生成 refresh token 值
func generateRefreshTokenValue() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate refresh token value failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// maskEmail 邮箱脱敏
func maskEmail(email string) string {
	if email == "" {
		return ""
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}
	local := parts[0]
	if len(local) <= 1 {
		return local + "**@" + parts[1]
	}
	return string(local[0]) + "**@" + parts[1]
}

// maskPhone 手机号脱敏
func maskPhone(phone string) string {
	if phone == "" {
		return ""
	}
	if len(phone) <= 7 {
		return phone
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}

// DecryptPhone 解密手机号（从 user 模块导出）
func DecryptPhone(cipher, openID string) (string, error) {
	return kms.DecryptPhone(cipher, openID)
}
