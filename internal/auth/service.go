package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/heliannuuthus/helios/internal/auth/cache"
	"github.com/heliannuuthus/helios/internal/auth/token"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/pkg/kms"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"
)

// Service 认证服务
type Service struct {
	db          *gorm.DB
	store       Store
	issuer      *token.Issuer
	idpManager  *IDPManager
	hermesCache *cache.HermesCache
}

// NewService 创建认证服务
func NewService(db *gorm.DB, hermesSvc *hermes.Service) (*Service, error) {
	issuer, err := token.NewIssuer()
	if err != nil {
		return nil, fmt.Errorf("create token issuer: %w", err)
	}

	return &Service{
		db:          db,
		store:       NewMemoryStore(), // TODO: 支持 Redis
		issuer:      issuer,
		idpManager:  NewIDPManager(),
		hermesCache: cache.NewHermesCache(hermesSvc),
	}, nil
}

// ============= Authorize =============

// Authorize 创建认证会话，返回 sessionID（用于设置 Cookie）
func (s *Service) Authorize(ctx context.Context, req *AuthorizeRequest) (string, error) {
	// 1. 验证 response_type（只允许 code）
	if req.ResponseType != "code" {
		return "", NewError(ErrUnsupportedResponseType, "response_type must be 'code'")
	}

	// 2. 验证客户端
	client, err := s.getClient(req.ClientID)
	if err != nil {
		return "", NewError(ErrInvalidClient, "client not found")
	}

	// 3. 验证重定向 URI
	if !client.ValidateRedirectURI(req.RedirectURI) {
		return "", NewError(ErrInvalidRequest, "invalid redirect_uri")
	}

	// 4. 验证 Application-Service 关系
	hasRelation, err := s.hermesCache.CheckApplicationServiceRelation(ctx, req.ClientID, req.Audience)
	if err != nil {
		return "", NewError(ErrServerError, fmt.Sprintf("check application service relation: %v", err))
	}
	if !hasRelation {
		return "", NewError(ErrAccessDenied, fmt.Sprintf("application %s has no access to service %s", req.ClientID, req.Audience))
	}

	// 5. 创建会话
	sessionID := GenerateSessionID()
	session := &Session{
		ID:                  sessionID,
		ClientID:            req.ClientID,
		Audience:            req.Audience,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		State:               req.State,
		Scope:               req.Scope,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := s.store.SaveSession(ctx, session); err != nil {
		return "", NewError(ErrServerError, "failed to create session")
	}

	logger.Infof("[Auth] 创建认证会话 - SessionID: %s, ClientID: %s", sessionID, req.ClientID)

	return sessionID, nil
}

// GetIDPConfigs 获取客户端允许的 IDPs 配置（从配置文件读取）
func (s *Service) GetIDPConfigs(clientID string) (*IDPsResponse, error) {
	// 1. 验证客户端
	client, err := s.getClient(clientID)
	if err != nil {
		return nil, NewError(ErrInvalidClient, "client not found")
	}

	// 2. 根据域返回该域下所有支持的 IDPs
	var idps []IDP
	switch client.Domain {
	case DomainCIAM:
		idps = []IDP{IDPWechatMP, IDPTTMP, IDPAlipayMP}
	case DomainPIAM:
		idps = []IDP{IDPWecom, IDPGithub, IDPGoogle}
	default:
		return nil, fmt.Errorf("unknown domain: %s", client.Domain)
	}

	// 3. 构建配置列表
	configs := make([]IDPConfig, 0, len(idps))
	for _, idp := range idps {
		idpConfig := IDPConfig{
			Type:  string(idp),
			Extra: make(map[string]interface{}),
		}

		// 根据 IDP 类型添加配置
		switch idp {
		case IDPWechatMP:
			if appid := config.GetString("idps.wxmp.appid"); appid != "" {
				idpConfig.ClientID = appid
			}
			idpConfig.AllowedScopes = s.getAllowedScopes("idps.wxmp")
			if config.GetBool("idps.wxmp.capture.required") {
				idpConfig.Capture = &CaptureConfig{
					Required: true,
					Type:     config.GetString("idps.wxmp.capture.type"),
					SiteKey:  config.GetString("idps.wxmp.capture.site_key"),
				}
			}
		case IDPTTMP:
			if appid := config.GetString("idps.tt.appid"); appid != "" {
				idpConfig.ClientID = appid
			}
			idpConfig.AllowedScopes = s.getAllowedScopes("idps.tt")
			if config.GetBool("idps.tt.capture.required") {
				idpConfig.Capture = &CaptureConfig{
					Required: true,
					Type:     config.GetString("idps.tt.capture.type"),
					SiteKey:  config.GetString("idps.tt.capture.site_key"),
				}
			}
		case IDPAlipayMP:
			if appid := config.GetString("idps.alipay.appid"); appid != "" {
				idpConfig.ClientID = appid
			}
			idpConfig.AllowedScopes = s.getAllowedScopes("idps.alipay")
			if config.GetBool("idps.alipay.capture.required") {
				idpConfig.Capture = &CaptureConfig{
					Required: true,
					Type:     config.GetString("idps.alipay.capture.type"),
					SiteKey:  config.GetString("idps.alipay.capture.site_key"),
				}
			}
		case IDPWecom:
			idpConfig.AllowedScopes = s.getAllowedScopes("idps.wecom")
		case IDPGithub:
			idpConfig.AllowedScopes = s.getAllowedScopes("idps.github")
		case IDPGoogle:
			idpConfig.AllowedScopes = s.getAllowedScopes("idps.google")
		}

		configs = append(configs, idpConfig)
	}

	return &IDPsResponse{IDPs: configs}, nil
}

// getAllowedScopes 从配置读取 connection 允许的 scopes
func (s *Service) getAllowedScopes(configPrefix string) []string {
	scopes := config.GetStringSlice(configPrefix + ".allowed_scopes")
	if len(scopes) == 0 {
		// 默认只允许 openid
		return []string{ScopeOpenID}
	}
	return scopes
}

// ============= Login =============

// Login 处理 IDP 登录
func (s *Service) Login(ctx context.Context, sessionID string, req *LoginRequest) (*LoginResponse, error) {
	// 1. 获取会话
	session, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
			// Session 过期或不存在，返回特定错误码供 handler 返回 412
			return nil, NewError(ErrInvalidRequest, "session not found or expired")
		}
		return nil, NewError(ErrServerError, err.Error())
	}

	// 2. 解析 connection 为 IDP
	idp := IDP(req.Connection)
	if idp == "" {
		return nil, NewError(ErrInvalidRequest, "connection is required")
	}

	// 3. 获取客户端并验证 IDP
	client, err := s.getClient(session.ClientID)
	if err != nil {
		return nil, NewError(ErrInvalidClient, "client not found")
	}

	if !client.ValidateIDP(idp) {
		return nil, NewError(ErrInvalidRequest, fmt.Sprintf("idp %s not allowed for this client", idp))
	}

	// 4. 检查前置认证需求（如人机验证）
	// 如果 connection 配置了 Capture 且 data 中没有验证结果，返回 require
	if require := s.checkPreAuthRequirement(idp, req.Data); require != "" {
		// 返回特殊响应，handler 会构造 InteractionRequiredResponse
		// 使用 Code 字段传递 require 信息（handler 会识别并转换）
		return &LoginResponse{
			Code: "require:" + require, // handler 会检查并转换为 InteractionRequiredResponse
		}, nil
	}

	// 5. 从 data 中获取认证凭证（根据 connection 类型不同）
	// OAuth2 connection（如 wechat:mp）需要 code
	code, ok := req.Data["code"]
	if !ok || code == "" {
		return nil, NewError(ErrInvalidRequest, "code is required in data for oauth2 connection")
	}

	// 6. 调用 IDP 换取用户信息
	idpResult, err := s.idpManager.Exchange(ctx, idp, code)
	if err != nil {
		logger.Errorf("[Auth] IDP 认证失败 - IDP: %s, Error: %v", idp, err)
		return nil, NewError(ErrAccessDenied, fmt.Sprintf("idp auth failed: %v", err))
	}

	// 7. 查找或创建用户（C 端 IDP 允许自动创建）
	user, err := s.findOrCreateUser(idp, idpResult)
	if err != nil {
		return nil, NewError(ErrServerError, fmt.Sprintf("user management failed: %v", err))
	}

	// 8. 处理 scope（降级逻辑）
	requestedScopes := ParseScopes(session.Scope)
	// 添加默认的 openid
	if !ContainsScope(requestedScopes, ScopeOpenID) {
		requestedScopes = append([]string{ScopeOpenID}, requestedScopes...)
	}

	// 获取 connection 允许的 scopes
	allowedScopes := s.getAllowedScopesForIDP(idp)

	// 计算交集
	grantedScopes := ScopeIntersection(requestedScopes, allowedScopes)

	// 检查：除了 openid 还有其他 scope 吗？
	hasNonOpenIDScope := false
	for _, scope := range grantedScopes {
		if scope != ScopeOpenID {
			hasNonOpenIDScope = true
			break
		}
	}

	if !hasNonOpenIDScope {
		// 构建错误描述
		requestedStr := JoinScopes(requestedScopes)
		allowedStr := JoinScopes(allowedScopes)
		return nil, NewError(ErrAccessDenied, fmt.Sprintf("No valid scopes granted. Requested: %s, Allowed by connection: %s", requestedStr, allowedStr))
	}

	grantedScopeStr := JoinScopes(grantedScopes)

	// 9. 更新会话
	session.UserID = user.OpenID
	session.IDP = idp
	session.GrantedScope = grantedScopeStr
	if err := s.store.UpdateSession(ctx, session); err != nil {
		return nil, NewError(ErrServerError, "failed to update session")
	}

	// 10. 生成授权码
	authCode := GenerateAuthorizationCode()
	authCodeObj := &AuthorizationCode{
		Code:                authCode,
		ClientID:            session.ClientID,
		Audience:            session.Audience, // 目标服务 ID
		RedirectURI:         session.RedirectURI,
		CodeChallenge:       session.CodeChallenge,
		CodeChallengeMethod: string(session.CodeChallengeMethod),
		Scope:               grantedScopeStr, // 使用实际授予的 scope
		UserID:              user.OpenID,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	if err := s.store.SaveAuthCode(ctx, authCodeObj); err != nil {
		return nil, NewError(ErrServerError, "failed to save authorization code")
	}

	// 11. 删除会话
	_ = s.store.DeleteSession(ctx, sessionID)

	// 12. 构建响应
	redirectURI := session.RedirectURI + "?code=" + url.QueryEscape(authCode)
	if session.State != "" {
		redirectURI += "&state=" + url.QueryEscape(session.State)
	}

	logger.Infof("[Auth] 登录成功 - OpenID: %s, IDP: %s, GrantedScope: %s", user.OpenID, idp, grantedScopeStr)

	return &LoginResponse{
		Code:        authCode,
		RedirectURI: redirectURI,
	}, nil
}

// getAllowedScopesForIDP 获取 IDP 允许的 scopes
func (s *Service) getAllowedScopesForIDP(idp IDP) []string {
	switch idp {
	case IDPWechatMP:
		return s.getAllowedScopes("idps.wxmp")
	case IDPTTMP:
		return s.getAllowedScopes("idps.tt")
	case IDPAlipayMP:
		return s.getAllowedScopes("idps.alipay")
	case IDPWecom:
		return s.getAllowedScopes("idps.wecom")
	case IDPGithub:
		return s.getAllowedScopes("idps.github")
	case IDPGoogle:
		return s.getAllowedScopes("idps.google")
	default:
		return []string{ScopeOpenID}
	}
}

// checkPreAuthRequirement 检查前置认证需求
func (s *Service) checkPreAuthRequirement(idp IDP, data map[string]string) string {
	// 检查该 IDP 是否配置了 Capture
	var captureRequired bool
	var captureType string
	switch idp {
	case IDPWechatMP:
		captureRequired = config.GetBool("idps.wxmp.capture.required")
		captureType = config.GetString("idps.wxmp.capture.type")
	case IDPTTMP:
		captureRequired = config.GetBool("idps.tt.capture.required")
		captureType = config.GetString("idps.tt.capture.type")
	case IDPAlipayMP:
		captureRequired = config.GetBool("idps.alipay.capture.required")
		captureType = config.GetString("idps.alipay.capture.type")
	}

	// 如果配置了 Capture 但 data 中没有验证结果，返回 require
	if captureRequired && captureType != "" {
		if _, ok := data["capture_token"]; !ok {
			return "captcha" // 返回 captcha，handler 会构造 InteractionRequiredResponse
		}
	}

	return ""
}

// ============= Token =============

// ExchangeToken 交换 Token
func (s *Service) ExchangeToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, req)
	case GrantTypeRefreshToken:
		return s.exchangeRefreshToken(ctx, req)
	default:
		return nil, NewError(ErrUnsupportedGrantType, "unsupported grant type")
	}
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// 1. 获取授权码
	authCode, err := s.store.GetAuthCode(ctx, req.Code)
	if err != nil {
		return nil, NewError(ErrInvalidGrant, "invalid or expired authorization code")
	}

	// 2. 验证客户端
	if req.ClientID != authCode.ClientID {
		return nil, NewError(ErrInvalidGrant, "client_id mismatch")
	}

	// 3. 验证重定向 URI
	if req.RedirectURI != authCode.RedirectURI {
		return nil, NewError(ErrInvalidGrant, "redirect_uri mismatch")
	}

	// 4. 验证 PKCE
	if !VerifyCodeChallenge(CodeChallengeMethod(authCode.CodeChallengeMethod), authCode.CodeChallenge, req.CodeVerifier) {
		return nil, NewError(ErrInvalidGrant, "invalid code_verifier")
	}

	// 5. 标记授权码已使用
	if err := s.store.MarkAuthCodeUsed(ctx, req.Code); err != nil {
		return nil, NewError(ErrServerError, "failed to mark code as used")
	}

	// 6. 获取用户和客户端
	user, err := s.getUserByOpenID(authCode.UserID)
	if err != nil {
		return nil, NewError(ErrServerError, "user not found")
	}

	client, err := s.getClient(authCode.ClientID)
	if err != nil {
		return nil, NewError(ErrInvalidClient, "client not found")
	}

	// 7. 生成 Token（使用授权码中的 scope 和 audience）
	return s.generateTokens(ctx, client, user, authCode.Audience, authCode.Scope)
}

func (s *Service) exchangeRefreshToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// 1. 从 Store 获取 Refresh Token
	refreshToken, err := s.store.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, NewError(ErrInvalidGrant, "invalid refresh token")
	}

	// 2. 检查是否有效
	if !refreshToken.IsValid() {
		return nil, NewError(ErrInvalidGrant, "refresh token expired or revoked")
	}

	// 3. 验证客户端
	if req.ClientID != refreshToken.ClientID {
		return nil, NewError(ErrInvalidGrant, "client_id mismatch")
	}

	// 4. 获取用户和客户端
	user, err := s.getUserByOpenID(refreshToken.UserID)
	if err != nil {
		return nil, NewError(ErrServerError, "user not found")
	}

	client, err := s.getClient(refreshToken.ClientID)
	if err != nil {
		return nil, NewError(ErrInvalidClient, "client not found")
	}

	// 5. 生成新的 Access Token（使用 refresh token 中的 scope 和 audience）
	token, err := s.generateTokens(ctx, client, user, refreshToken.Audience, refreshToken.Scope)
	if err != nil {
		return nil, err
	}

	// 保持 refresh token 不变（不轮转）
	token.RefreshToken = refreshToken.Token

	return token, nil
}

// ============= Revoke =============

// RevokeToken 撤销 Token
func (s *Service) RevokeToken(ctx context.Context, token string) error {
	return s.store.RevokeRefreshToken(ctx, token)
}

// RevokeAllTokens 撤销用户所有 Token
func (s *Service) RevokeAllTokens(ctx context.Context, userID string) error {
	return s.store.RevokeUserRefreshTokens(ctx, userID)
}

// ============= Introspect =============

// Introspect Token 内省
func (s *Service) Introspect(ctx context.Context, tokenString string, serviceJWT string) (*IntrospectResponse, error) {
	// 1. 验证 Service JWT
	serviceID, _, err := s.verifyServiceJWT(serviceJWT)
	if err != nil {
		return nil, NewError(ErrInvalidClient, fmt.Sprintf("invalid service jwt: %v", err))
	}

	// 2. 检查 jti 防重放（TODO: 实现 Redis 存储）
	// 这里先跳过，后续实现
	_ = serviceID // 暂时未使用，后续可用于日志

	// 3. 解析 Access Token（不验证，因为可能已过期）
	aud, iss, exp, iat, scope, err := s.issuer.ParseAccessTokenUnverified(tokenString)
	if err != nil {
		return &IntrospectResponse{Active: false}, nil
	}

	// 4. 验证 Token 签名和有效性
	identity, err := s.issuer.VerifyAccessToken(tokenString)
	if err != nil {
		return &IntrospectResponse{Active: false}, nil
	}

	// 5. 获取用户完整信息
	user, err := s.getUserByOpenID(identity.UserID)
	if err != nil {
		return &IntrospectResponse{Active: false}, nil
	}

	// 6. 解密手机号（如果有）
	var phone string
	if user.PhoneCipher != nil {
		decryptedPhone, err := kms.DecryptPhone(*user.PhoneCipher, user.OpenID)
		if err == nil {
			phone = decryptedPhone
		}
	}

	// 7. 构建响应（完整信息，未脱敏）
	resp := &IntrospectResponse{
		Active:   true,
		Sub:      identity.UserID,
		Aud:      aud,
		Iss:      iss,
		Exp:      exp,
		Iat:      iat,
		Scope:    scope,
		Nickname: identity.Nickname,
		Picture:  identity.Picture,
		Email:    identity.Email,
		Phone:    phone,
	}

	// 如果 Token 中没有，从数据库补充
	if resp.Nickname == "" {
		resp.Nickname = user.Name
	}
	if resp.Picture == "" {
		resp.Picture = user.Picture
	}
	if resp.Email == "" && user.Email != nil {
		resp.Email = *user.Email
	}
	if resp.Phone == "" && phone != "" {
		resp.Phone = phone
	}

	logger.Infof("[Auth] Token 内省成功 - ServiceID: %s, UserID: %s", serviceID, identity.UserID)

	return resp, nil
}

// verifyServiceJWT 验证 Service JWT
func (s *Service) verifyServiceJWT(tokenString string) (serviceID string, jti string, err error) {
	// 解析 JWT 获取 service_id（不验证签名）
	token, parseErr := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if parseErr != nil {
		return "", "", parseErr
	}

	sub, ok := token.Subject()
	if !ok {
		return "", "", errors.New("missing sub in service jwt")
	}

	jtiVal, _ := token.JwtID()

	// 从缓存获取带解密密钥的 Service
	svcWithKey, err := s.hermesCache.GetServiceWithKey(context.Background(), sub)
	if err != nil {
		return "", "", fmt.Errorf("service not found: %w", err)
	}

	// 验证 JWT 签名
	verifiedServiceID, verifiedJti, verifyErr := s.issuer.VerifyServiceJWT(tokenString, svcWithKey.Key)
	if verifyErr != nil {
		return "", "", fmt.Errorf("verify service jwt: %w", verifyErr)
	}

	// 返回验证后的 serviceID 和 jti（如果 jtiVal 为空则使用 verifiedJti）
	if jtiVal == "" {
		jtiVal = verifiedJti
	}

	return verifiedServiceID, jtiVal, nil
}

// ============= UserInfo =============

// GetUserInfo 获取用户信息（根据 scope 返回，脱敏）
func (s *Service) GetUserInfo(identity *Identity) (*UserInfoResponse, error) {
	user, err := s.getUserByOpenID(identity.UserID)
	if err != nil {
		return nil, err
	}

	resp := &UserInfoResponse{
		Sub: identity.UserID,
	}

	scopes := ParseScopes(identity.Scope)

	// 根据 scope 返回字段
	if ContainsScope(scopes, ScopeProfile) {
		resp.Nickname = identity.Nickname
		resp.Picture = identity.Picture
		// 如果 Token 中没有，从数据库获取
		if resp.Nickname == "" {
			resp.Nickname = user.Name
		}
		if resp.Picture == "" {
			resp.Picture = user.Picture
		}
	}

	if ContainsScope(scopes, ScopeEmail) {
		email := identity.Email
		if email == "" && user.Email != nil {
			email = *user.Email
		}
		resp.Email = MaskEmail(email)
	}

	if ContainsScope(scopes, ScopePhone) {
		phone := identity.Phone
		if phone == "" && user.PhoneCipher != nil {
			decryptedPhone, err := kms.DecryptPhone(*user.PhoneCipher, user.OpenID)
			if err == nil {
				phone = decryptedPhone
			}
		}
		resp.Phone = MaskPhone(phone)
	}

	return resp, nil
}

// UpdateUserInfo 更新用户信息
func (s *Service) UpdateUserInfo(identity *Identity, req *UpdateUserInfoRequest) (*UserInfoResponse, error) {
	user, err := s.getUserByOpenID(identity.UserID)
	if err != nil {
		return nil, err
	}

	updates := make(map[string]any)
	if req.Nickname != "" {
		updates["name"] = req.Nickname
	}
	if req.Picture != "" {
		updates["picture"] = req.Picture
	}

	if len(updates) > 0 {
		if err := s.db.Model(user).Updates(updates).Error; err != nil {
			return nil, err
		}
	}

	return s.GetUserInfo(identity)
}

// ============= Helper Methods =============

func (s *Service) getClient(clientID string) (*Client, error) {
	var client Client
	if err := s.db.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

func (s *Service) getUserByOpenID(openid string) (*User, error) {
	var user User
	if err := s.db.Where("openid = ?", openid).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) findOrCreateUser(idp IDP, result *IDPResult) (*User, error) {
	domain := idp.GetDomain()

	// 1. 查找已有身份（通过 idp 和 t_openid）
	var identity UserIdentity
	err := s.db.Where("idp = ? AND t_openid = ?", idp, result.ProviderID).First(&identity).Error

	if err == nil {
		// 找到身份，获取用户
		var user User
		if err := s.db.Where("openid = ?", identity.OpenID).First(&user).Error; err != nil {
			return nil, err
		}
		s.db.Model(&user).Update("last_login_at", time.Now())
		logger.Infof("[Auth] 找到已有用户 - OpenID: %s, IDP: %s", user.OpenID, idp)
		return &user, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// 2. 检查是否支持自动创建
	if !idp.SupportsAutoCreate() {
		return nil, errors.New("user not found and auto-create not supported for this idp")
	}

	// 3. 创建新用户
	now := time.Now()
	user := User{
		OpenID:      GenerateOpenID(),
		Domain:      domain,
		Name:        generateRandomName(),
		Picture:     generateRandomAvatar(result.ProviderID),
		LastLoginAt: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return err
		}

		identity := UserIdentity{
			OpenID:    user.OpenID,
			IDP:       idp,
			TOpenID:   result.ProviderID,
			RawData:   result.RawData,
			CreatedAt: now,
			UpdatedAt: now,
		}

		return tx.Create(&identity).Error
	})

	if err != nil {
		return nil, err
	}

	logger.Infof("[Auth] 创建新用户 - OpenID: %s, IDP: %s", user.OpenID, idp)
	return &user, nil
}

func (s *Service) generateTokens(ctx context.Context, client *Client, user *User, audience string, scope string) (*TokenResponse, error) {
	now := time.Now()

	// 1. 验证 Application-Service 关系
	hasRelation, err := s.hermesCache.CheckApplicationServiceRelation(ctx, client.ClientID, audience)
	if err != nil {
		return nil, fmt.Errorf("check application service relation: %w", err)
	}
	if !hasRelation {
		return nil, NewError(ErrAccessDenied, fmt.Sprintf("application %s has no access to service %s", client.ClientID, audience))
	}

	// 2. 获取 Service 和域密钥
	svcWithKey, err := s.hermesCache.GetServiceWithKey(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("get service: %w", err)
	}

	// 获取域签名密钥
	domainWithKey, err := s.hermesCache.GetDomain(ctx, string(client.Domain))
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}

	// 将服务密钥转换为 JWK
	serviceEncryptKey, err := jwk.Import(svcWithKey.Key)
	if err != nil {
		return nil, fmt.Errorf("import service key: %w", err)
	}

	// 将域签名密钥转换为 JWK
	signKey, err := jwk.ParseKey(domainWithKey.SignKey)
	if err != nil {
		return nil, fmt.Errorf("parse sign key: %w", err)
	}

	// 3. 计算 TTL（优先使用服务配置，其次使用客户端配置，最后使用全局配置）
	accessTTL := time.Duration(svcWithKey.AccessTokenExpiresIn) * time.Second
	if accessTTL == 0 {
		accessTTL = time.Duration(client.AccessTokenExpiresIn) * time.Second
	}
	if accessTTL == 0 {
		accessTTL = time.Duration(config.GetInt("auth.expires-in")) * time.Second
	}

	refreshTTL := time.Duration(svcWithKey.RefreshTokenExpiresIn) * time.Second
	if refreshTTL == 0 {
		refreshTTL = time.Duration(client.RefreshTokenExpiresIn) * time.Second
	}
	if refreshTTL == 0 {
		refreshTTL = time.Duration(config.GetInt("auth.refresh-expires-in")) * 24 * time.Hour
	}

	// 4. 解析 scope，确定要包含哪些用户信息
	scopes := ParseScopes(scope)

	// 构建 SubjectClaims（加密到 sub）
	subjectClaims := &token.SubjectClaims{
		OpenID: user.OpenID,
	}

	// 根据 scope 添加用户信息
	if ContainsScope(scopes, ScopeProfile) {
		subjectClaims.Nickname = user.Name
		subjectClaims.Picture = user.Picture
	}

	if ContainsScope(scopes, ScopeEmail) && user.Email != nil {
		subjectClaims.Email = *user.Email
	}

	if ContainsScope(scopes, ScopePhone) && user.PhoneCipher != nil {
		// 解密手机号
		phone, err := kms.DecryptPhone(*user.PhoneCipher, user.OpenID)
		if err == nil {
			subjectClaims.Phone = phone
		}
	}

	// 5. 创建 Access Token（使用新版本 API）
	accessToken, err := s.issuer.Issue(
		subjectClaims,
		client.ClientID, // cli
		audience,        // aud
		serviceEncryptKey,
		signKey,
		scope,
		accessTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}

	resp := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTTL.Seconds()),
		Scope:       scope,
	}

	// 6. 只有 scope 包含 offline_access 时才返回 refresh_token
	if ContainsScope(scopes, ScopeOfflineAccess) {
		// 清理旧的 Refresh Token
		s.cleanupOldRefreshTokens(ctx, user.OpenID, client.ClientID)

		// 创建新的 Refresh Token
		refreshToken := &RefreshToken{
			Token:     GenerateRefreshTokenValue(),
			UserID:    user.OpenID,
			ClientID:  client.ClientID,
			Audience:  audience, // 新增
			Scope:     scope,
			ExpiresAt: now.Add(refreshTTL),
			CreatedAt: now,
		}

		if err := s.store.SaveRefreshToken(ctx, refreshToken); err != nil {
			return nil, fmt.Errorf("create refresh token: %w", err)
		}

		resp.RefreshToken = refreshToken.Token
	}

	return resp, nil
}

func (s *Service) cleanupOldRefreshTokens(ctx context.Context, userID, clientID string) {
	maxTokens := config.GetInt("auth.max-refresh-token")
	if maxTokens <= 0 {
		maxTokens = 10
	}

	tokens, err := s.store.ListUserRefreshTokens(ctx, userID, clientID)
	if err != nil {
		return
	}

	if len(tokens) >= maxTokens {
		// 撤销多余的 token（保留最新的 maxTokens-1 个）
		for i := maxTokens - 1; i < len(tokens); i++ {
			_ = s.store.RevokeRefreshToken(ctx, tokens[i].Token)
		}
	}
}

func generateRandomName() string {
	adjectives := []string{"快乐的", "聪明的", "勇敢的", "温柔的", "活泼的", "安静的", "优雅的", "幽默的"}
	nouns := []string{"小猫", "小狗", "小鸟", "小鱼", "小兔", "小熊", "小鹿", "小羊"}

	adjIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	nounIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))

	return adjectives[adjIndex.Int64()] + nouns[nounIndex.Int64()] + fmt.Sprintf("%04d", time.Now().Unix()%10000)
}

func generateRandomAvatar(seed string) string {
	hash := 0
	for _, c := range seed {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	return fmt.Sprintf("https://api.dicebear.com/7.x/avataaars/svg?seed=%s&size=200", fmt.Sprintf("user%d", hash%10))
}

// GetJWKS 获取 JWKS（根据 client_id 返回其所属域的公钥）
func (s *Service) GetJWKS(ctx context.Context, clientID string) (map[string]interface{}, error) {
	// 1. 获取 Application
	app, err := s.hermesCache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, NewError(ErrInvalidClient, "client not found")
	}

	// 2. 获取域信息和公钥
	domain, err := s.hermesCache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, NewError(ErrServerError, fmt.Sprintf("domain not found: %v", err))
	}

	// 3. 解析签名密钥获取公钥
	signKey, err := jwk.ParseKey(domain.SignKey)
	if err != nil {
		return nil, NewError(ErrServerError, fmt.Sprintf("parse sign key: %v", err))
	}

	// 获取公钥
	publicKey, err := signKey.PublicKey()
	if err != nil {
		return nil, NewError(ErrServerError, fmt.Sprintf("get public key: %v", err))
	}

	// 4. 构建 JWKS 响应
	// 使用 jwk.Set 来构建 JWKS
	set := jwk.NewSet()
	_ = set.AddKey(publicKey)

	// 将 Set 序列化为 JSON 后再解析为 map
	jsonBytes, err := json.Marshal(set)
	if err != nil {
		return nil, NewError(ErrServerError, fmt.Sprintf("marshal jwks: %v", err))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, NewError(ErrServerError, fmt.Sprintf("unmarshal jwks: %v", err))
	}

	return result, nil
}
