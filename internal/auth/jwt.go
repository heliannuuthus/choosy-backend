package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"choosy-backend/internal/config"
	"choosy-backend/internal/logger"
	"choosy-backend/internal/models"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"
)

var (
	jwsKey jwk.Key
	jweKey jwk.Key
)

func generateID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// b64URLDecode 解码 base64url 字符串
func b64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// GetJWSKey 获取签名密钥
func GetJWSKey() (jwk.Key, error) {
	if jwsKey != nil {
		return jwsKey, nil
	}

	signKeyStr := config.GetString("kms.token.sign-key")
	if signKeyStr == "" {
		return nil, errors.New("kms.token.sign-key 未配置")
	}

	// 从 base64url 解码 JWK JSON
	jsonBytes, err := b64URLDecode(signKeyStr)
	if err != nil {
		return nil, fmt.Errorf("解码签名密钥失败: %w", err)
	}

	// 解析 JWK
	key, err := jwk.ParseKey(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("解析签名密钥失败: %w", err)
	}

	jwsKey = key
	kid, _ := key.KeyID()
	alg, _ := key.Algorithm()
	logger.Infof("[Auth] JWS 签名密钥加载成功 - Kid: %s, Alg: %s", kid, alg)

	return jwsKey, nil
}

// GetJWEKey 获取加密密钥
func GetJWEKey() (jwk.Key, error) {
	if jweKey != nil {
		return jweKey, nil
	}

	encKeyStr := config.GetString("kms.token.enc-key")
	if encKeyStr == "" {
		return nil, errors.New("kms.token.enc-key 未配置")
	}

	// 从 base64url 解码 JWK JSON
	jsonBytes, err := b64URLDecode(encKeyStr)
	if err != nil {
		return nil, fmt.Errorf("解码加密密钥失败: %w", err)
	}

	// 解析 JWK
	key, err := jwk.ParseKey(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("解析加密密钥失败: %w", err)
	}

	jweKey = key
	kid, _ := key.KeyID()
	alg, _ := key.Algorithm()
	logger.Infof("[Auth] JWE 加密密钥加载成功 - Kid: %s, Alg: %s", kid, alg)

	return jweKey, nil
}

func cleanupOldRefreshTokens(db *gorm.DB, openid string) {
	maxTokens := config.GetInt("auth.max-refresh-token")

	var tokens []models.RefreshToken
	db.Where("openid = ?", openid).Order("created_at DESC").Find(&tokens)

	if len(tokens) >= maxTokens {
		tokensToDelete := tokens[maxTokens-1:]
		for _, t := range tokensToDelete {
			db.Delete(&t)
		}
	}
}

const base62Chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func base62Encode(data []byte) string {
	num := new(big.Int).SetBytes(data)
	if num.Sign() == 0 {
		return string(base62Chars[0])
	}

	base := big.NewInt(62)
	result := make([]byte, 0)

	for num.Sign() > 0 {
		mod := new(big.Int)
		num.DivMod(num, base, mod)
		result = append(result, base62Chars[mod.Int64()])
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

func generateRefreshToken() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return base62Encode(bytes)
}

// createAccessToken 创建 access token（JWE 嵌套 JWS）
func createAccessToken(identity *Identity, idp string) (string, error) {
	now := time.Now()

	logger.Infof("[Auth] 开始生成 Access Token - OpenID: %s, IDP: %s", identity.OpenID, idp)

	// 1. 获取密钥
	signKey, err := GetJWSKey()
	if err != nil {
		logger.Errorf("[Auth] 获取签名密钥失败: %v", err)
		return "", err
	}

	encKey, err := GetJWEKey()
	if err != nil {
		logger.Errorf("[Auth] 获取加密密钥失败: %v", err)
		return "", err
	}

	// 2. 创建 JWT claims
	expiresIn := config.GetInt("auth.expires-in")
	token := jwt.New()

	_ = token.Set(jwt.IssuerKey, config.GetString("auth.issuer"))
	// aud 格式: issuer:idp，如 choosy:wechat:mp
	audience := fmt.Sprintf("%s:%s", config.GetString("auth.issuer"), idp)
	_ = token.Set(jwt.AudienceKey, audience)
	_ = token.Set(jwt.IssuedAtKey, now.Unix())
	_ = token.Set(jwt.ExpirationKey, now.Add(time.Duration(expiresIn)*time.Second).Unix())

	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	_ = token.Set(jwt.JwtIDKey, hex.EncodeToString(jtiBytes))

	// 将 identity 信息作为自定义 claims
	_ = token.Set("openid", identity.OpenID)
	_ = token.Set("nickname", identity.Nickname)
	_ = token.Set("avatar", identity.Avatar)

	// 3. 签名 JWT (JWS)
	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), signKey))
	if err != nil {
		logger.Errorf("[Auth] JWT 签名失败: %v", err)
		return "", fmt.Errorf("JWT 签名失败: %w", err)
	}

	kid, _ := signKey.KeyID()
	logger.Infof("[Auth] JWT 签名成功 - Kid: %s, Size: %d bytes", kid, len(signedToken))

	// 4. 加密 JWT (JWE) - 使用直接密钥加密
	encryptedToken, err := jwe.Encrypt(signedToken,
		jwe.WithKey(jwa.DIRECT(), encKey),        // DIRECT 密钥加密算法
		jwe.WithContentEncryption(jwa.A256GCM()), // A256GCM 内容加密算法
	)
	if err != nil {
		logger.Errorf("[Auth] JWT 加密失败: %v", err)
		return "", fmt.Errorf("JWT 加密失败: %w", err)
	}

	logger.Infof("[Auth] Access Token 生成成功 - OpenID: %s, Aud: %s, Kid: %s, Size: %d bytes",
		identity.OpenID, audience, kid, len(encryptedToken))

	return string(encryptedToken), nil
}

// LoginParams 登录参数
type LoginParams struct {
	IDP      string  // 身份提供方，如 wechat:mp
	TOpenID  string  // 第三方 openid
	UnionID  string  // unionid（可选）
	Nickname string  // 昵称
	Avatar   string  // 头像
	RawData  *string // 原始授权数据（可选）
}

// selectOrCreateUser 查找或创建用户（支持 unionid 和手机号关联）
func selectOrCreateUser(db *gorm.DB, params *LoginParams) (*models.User, error) {
	logger.Infof("[Auth] 开始查询/创建用户 - IDP: %s, T_OpenID: %s, UnionID: %s",
		params.IDP, params.TOpenID, params.UnionID)

	now := time.Now()

	// 1. 先查当前 idp + t_openid 是否存在
	var identity models.UserIdentity
	err := db.Where("idp = ? AND t_openid = ?", params.IDP, params.TOpenID).First(&identity).Error

	if err == nil {
		// 找到了，直接查用户
		var user models.User
		if err := db.Where("openid = ?", identity.OpenID).First(&user).Error; err != nil {
			logger.Errorf("[Auth] 用户身份存在但用户不存在 - OpenID: %s, Error: %v", identity.OpenID, err)
			return nil, err
		}

		// 更新最后登录时间
		db.Model(&user).Update("last_login_at", now)

		logger.Infof("[Auth] 找到现有用户 - OpenID: %s, IDP: %s, Nickname: %s",
			user.OpenID, params.IDP, user.Nickname)
		return &user, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Errorf("[Auth] 查询用户身份失败 - IDP: %s, T_OpenID: %s, Error: %v",
			params.IDP, params.TOpenID, err)
		return nil, err
	}

	// 2. 没找到，如果有 unionid，尝试通过 unionid 关联
	var existingOpenID string
	if params.UnionID != "" {
		unionIDP := getUnionIDP(params.IDP)
		var unionIdentity models.UserIdentity
		err := db.Where("idp = ? AND t_openid = ?", unionIDP, params.UnionID).First(&unionIdentity).Error
		if err == nil {
			existingOpenID = unionIdentity.OpenID
			logger.Infof("[Auth] 通过 UnionID 找到已有用户 - OpenID: %s, UnionIDP: %s",
				existingOpenID, unionIDP)
		}
	}

	// 3. 开始事务：创建用户或绑定身份
	var user models.User
	err = db.Transaction(func(tx *gorm.DB) error {
		if existingOpenID != "" {
			// 已有用户，只需绑定新身份
			if err := tx.Where("openid = ?", existingOpenID).First(&user).Error; err != nil {
				return err
			}
		} else {
			// 创建新用户
			user = models.User{
				OpenID:      generateID(),
				Nickname:    params.Nickname,
				Avatar:      params.Avatar,
				Gender:      0,
				Status:      0,
				LastLoginAt: &now,
				CreatedAt:   now,
				UpdatedAt:   now,
			}
			if err := tx.Create(&user).Error; err != nil {
				return err
			}
			logger.Infof("[Auth] 创建新用户 - OpenID: %s, Nickname: %s", user.OpenID, user.Nickname)
		}

		// 插入当前 idp 身份
		newIdentity := models.UserIdentity{
			OpenID:    user.OpenID,
			IDP:       params.IDP,
			TOpenID:   params.TOpenID,
			RawData:   params.RawData,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := tx.Create(&newIdentity).Error; err != nil {
			return err
		}
		logger.Infof("[Auth] 绑定身份 - OpenID: %s, IDP: %s, T_OpenID: %s",
			user.OpenID, params.IDP, params.TOpenID)

		// 如果有 unionid 且之前没有记录，也插入
		if params.UnionID != "" && existingOpenID == "" {
			unionIDP := getUnionIDP(params.IDP)
			unionIdentity := models.UserIdentity{
				OpenID:    user.OpenID,
				IDP:       unionIDP,
				TOpenID:   params.UnionID,
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := tx.Create(&unionIdentity).Error; err != nil {
				return err
			}
			logger.Infof("[Auth] 绑定 UnionID - OpenID: %s, IDP: %s, UnionID: %s",
				user.OpenID, unionIDP, params.UnionID)
		}

		return nil
	})

	if err != nil {
		logger.Errorf("[Auth] 创建用户/绑定身份失败 - Error: %v", err)
		return nil, err
	}

	// 更新最后登录时间（如果是已有用户绑定新身份）
	if existingOpenID != "" {
		db.Model(&user).Update("last_login_at", now)
	}

	return &user, nil
}

// getUnionIDP 根据 idp 获取对应的 unionid idp
func getUnionIDP(idp string) string {
	switch idp {
	case IDPWechatMP, IDPWechatOA:
		return IDPWechatUnionID
	case IDPTTMP:
		return IDPTTUnionID
	default:
		return idp + ":unionid"
	}
}

// GenerateTokenPair 生成 access_token 和 refresh_token
func GenerateTokenPair(db *gorm.DB, params *LoginParams) (*TokenPair, error) {
	logger.Infof("[Auth] 开始生成 Token 对 - IDP: %s, T_OpenID: %s", params.IDP, params.TOpenID)

	now := time.Now()

	user, err := selectOrCreateUser(db, params)
	if err != nil {
		logger.Errorf("[Auth] 保存用户信息失败 - IDP: %s, T_OpenID: %s, Error: %v",
			params.IDP, params.TOpenID, err)
		return nil, fmt.Errorf("保存用户信息失败: %w", err)
	}

	identity := &Identity{
		OpenID:   user.OpenID,
		Nickname: user.Nickname,
		Avatar:   user.Avatar,
	}

	logger.Infof("[Auth] 准备生成 Access Token - OpenID: %s, IDP: %s", user.OpenID, params.IDP)

	accessToken, err := createAccessToken(identity, params.IDP)
	if err != nil {
		logger.Errorf("[Auth] 生成 Access Token 失败 - OpenID: %s, Error: %v", user.OpenID, err)
		return nil, fmt.Errorf("生成 access_token 失败: %w", err)
	}

	refreshToken := generateRefreshToken()
	refreshExpiresIn := config.GetInt("auth.refresh-expires-in")
	expiresAt := now.Add(time.Duration(refreshExpiresIn) * 24 * time.Hour)

	cleanupOldRefreshTokens(db, user.OpenID)

	dbToken := models.RefreshToken{
		OpenID:    user.OpenID,
		Token:     refreshToken,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := db.Create(&dbToken).Error; err != nil {
		logger.Errorf("[Auth] 存储 Refresh Token 失败 - OpenID: %s, Error: %v", user.OpenID, err)
		return nil, fmt.Errorf("存储 refresh_token 失败: %w", err)
	}

	logger.Infof("[Auth] Token 对生成成功 - OpenID: %s, Aud: %s:%s, ExpiresIn: %ds",
		user.OpenID, config.GetString("auth.issuer"), params.IDP, config.GetInt("auth.expires-in"))

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    config.GetInt("auth.expires-in"),
	}, nil
}

// VerifyAccessToken 验证 access_token 并解密身份信息
func VerifyAccessToken(tokenString string) (*Identity, error) {
	logger.Infof("[Auth] 开始验证 Token - Size: %d bytes", len(tokenString))

	// 1. 获取密钥
	encKey, err := GetJWEKey()
	if err != nil {
		logger.Errorf("[Auth] 获取加密密钥失败: %v", err)
		return nil, err
	}

	signKey, err := GetJWSKey()
	if err != nil {
		logger.Errorf("[Auth] 获取签名密钥失败: %v", err)
		return nil, err
	}

	// 2. 解密 JWE - 使用直接密钥解密
	decrypted, err := jwe.Decrypt([]byte(tokenString),
		jwe.WithKey(jwa.DIRECT(), encKey),
	)
	if err != nil {
		logger.Errorf("[Auth] JWT 解密失败: %v", err)
		return nil, fmt.Errorf("JWT 解密失败: %w", err)
	}

	logger.Infof("[Auth] JWT 解密成功 - Decrypted Size: %d bytes", len(decrypted))

	// 3. 验证 JWS 签名并解析
	token, err := jwt.Parse(decrypted,
		jwt.WithKey(jwa.EdDSA(), signKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		logger.Errorf("[Auth] JWT 验证失败: %v", err)
		return nil, fmt.Errorf("JWT 验证失败: %w", err)
	}

	issuer, _ := token.Issuer()
	jti, _ := token.JwtID()
	logger.Infof("[Auth] JWT 验证成功 - Issuer: %s, JTI: %s", issuer, jti)

	// 4. 提取 identity 信息
	var openid, nickname, avatar string
	_ = token.Get("openid", &openid)
	_ = token.Get("nickname", &nickname)
	_ = token.Get("avatar", &avatar)

	identity := &Identity{
		OpenID:   openid,
		Nickname: nickname,
		Avatar:   avatar,
	}

	aud, _ := token.Audience()
	logger.Infof("[Auth] Token 验证成功 - OpenID: %s, Aud: %v", identity.OpenID, aud)

	return identity, nil
}

// RefreshTokens 刷新 token（刷新时保持原 IDP）
func RefreshTokens(db *gorm.DB, refreshToken string, idp string) (*TokenPair, error) {
	var dbToken models.RefreshToken
	if err := db.Where("token = ?", refreshToken).First(&dbToken).Error; err != nil {
		return nil, errors.New("refresh_token 无效")
	}

	if time.Now().After(dbToken.ExpiresAt) {
		db.Delete(&dbToken)
		return nil, errors.New("refresh_token 已过期")
	}

	var user models.User
	if err := db.Where("openid = ?", dbToken.OpenID).First(&user).Error; err != nil {
		return nil, errors.New("用户不存在")
	}

	identity := &Identity{
		OpenID:   user.OpenID,
		Nickname: user.Nickname,
		Avatar:   user.Avatar,
	}

	accessToken, err := createAccessToken(identity, idp)
	if err != nil {
		return nil, fmt.Errorf("生成 access_token 失败: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    config.GetInt("auth.expires-in"),
	}, nil
}

// RevokeRefreshToken 撤销单个 refresh_token
func RevokeRefreshToken(db *gorm.DB, refreshToken string) bool {
	result := db.Where("token = ?", refreshToken).Delete(&models.RefreshToken{})
	return result.RowsAffected > 0
}

// RevokeAllRefreshTokens 撤销用户所有 refresh_token
func RevokeAllRefreshTokens(db *gorm.DB, openid string) int64 {
	result := db.Where("openid = ?", openid).Delete(&models.RefreshToken{})
	return result.RowsAffected
}
