package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"choosy-backend/internal/config"
	"choosy-backend/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var (
	jwsKey *JWK
	jweKey *JWK
)

func b64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func decodeJWK(encoded string) (*JWK, error) {
	jsonBytes, err := b64URLDecode(encoded)
	if err != nil {
		return nil, err
	}
	var key JWK
	if err := json.Unmarshal(jsonBytes, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// GetJWSKey 获取签名密钥
func GetJWSKey() (*JWK, error) {
	if jwsKey != nil {
		return jwsKey, nil
	}

	signKey := config.GetString("auth.token.sign_key")
	if signKey == "" {
		return nil, errors.New("auth.token.sign_key 未配置")
	}

	var err error
	jwsKey, err = decodeJWK(signKey)
	return jwsKey, err
}

// GetJWEKey 获取加密密钥
func GetJWEKey() (*JWK, error) {
	if jweKey != nil {
		return jweKey, nil
	}

	encKey := config.GetString("auth.token.enc_key")
	if encKey == "" {
		return nil, errors.New("auth.token.enc_key 未配置")
	}

	var err error
	jweKey, err = decodeJWK(encKey)
	return jweKey, err
}

func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func encryptIdentity(identity *Identity) (string, error) {
	plaintext, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}

	jweK, err := GetJWEKey()
	if err != nil {
		return "", err
	}

	keyBytes, err := b64URLDecode(jweK.K)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	result := append(nonce, ciphertext...)

	return b64URLEncode(result), nil
}

func decryptIdentity(encrypted string) (*Identity, error) {
	data, err := b64URLDecode(encrypted)
	if err != nil {
		return nil, err
	}

	if len(data) < 12 {
		return nil, errors.New("密文太短")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	jweK, err := GetJWEKey()
	if err != nil {
		return nil, err
	}

	keyBytes, err := b64URLDecode(jweK.K)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var identity Identity
	if err := json.Unmarshal(plaintext, &identity); err != nil {
		return nil, err
	}

	return &identity, nil
}

func getSigningKey() (ed25519.PrivateKey, error) {
	jwsK, err := GetJWSKey()
	if err != nil {
		return nil, err
	}

	privateBytes, err := b64URLDecode(jwsK.D)
	if err != nil {
		return nil, err
	}

	publicBytes, err := b64URLDecode(jwsK.X)
	if err != nil {
		return nil, err
	}

	privateKey := make([]byte, ed25519.PrivateKeySize)
	copy(privateKey[:32], privateBytes)
	copy(privateKey[32:], publicBytes)

	return ed25519.PrivateKey(privateKey), nil
}

func getVerifyKey() (ed25519.PublicKey, error) {
	jwsK, err := GetJWSKey()
	if err != nil {
		return nil, err
	}

	publicBytes, err := b64URLDecode(jwsK.X)
	if err != nil {
		return nil, err
	}

	return ed25519.PublicKey(publicBytes), nil
}

func createAccessToken(identity *Identity) (string, error) {
	now := time.Now()

	encryptedSub, err := encryptIdentity(identity)
	if err != nil {
		return "", fmt.Errorf("加密身份信息失败: %w", err)
	}

	jwsK, err := GetJWSKey()
	if err != nil {
		return "", err
	}

	privateKey, err := getSigningKey()
	if err != nil {
		return "", err
	}

	jti := make([]byte, 16)
	rand.Read(jti)

	expiresIn := config.GetInt("auth.expiresIn")

	claims := jwt.MapClaims{
		"iss": config.GetString("auth.issuer"),
		"aud": config.GetString("auth.audience"),
		"sub": encryptedSub,
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"jti": b64URLEncode(jti),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = jwsK.Kid

	return token.SignedString(privateKey)
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
		result = append([]byte{base62Chars[mod.Int64()]}, result...)
	}

	return string(result)
}

func generateRefreshToken() string {
	randomBytes := make([]byte, 24)
	rand.Read(randomBytes)
	return base62Encode(randomBytes)
}

func cleanupOldRefreshTokens(db *gorm.DB, openid string) {
	maxTokens := config.GetInt("auth.maxRefreshToken")

	var tokens []models.RefreshToken
	db.Where("openid = ?", openid).Order("created_at DESC").Find(&tokens)

	if len(tokens) >= maxTokens {
		tokensToDelete := tokens[maxTokens-1:]
		for _, t := range tokensToDelete {
			db.Delete(&t)
		}
	}
}

// GenerateTokenPair 生成 access_token 和 refresh_token
func GenerateTokenPair(db *gorm.DB, tOpenID, nickname, avatar string) (*TokenPair, error) {
	now := time.Now()

	user, err := upsertUser(db, tOpenID, nickname, avatar)
	if err != nil {
		return nil, fmt.Errorf("保存用户信息失败: %w", err)
	}

	identity := &Identity{
		OpenID:   user.OpenID,
		TOpenID:  user.TOpenID,
		Nickname: user.Nickname,
		Avatar:   user.Avatar,
	}

	accessToken, err := createAccessToken(identity)
	if err != nil {
		return nil, fmt.Errorf("生成 access_token 失败: %w", err)
	}

	refreshToken := generateRefreshToken()
	refreshExpiresIn := config.GetInt("auth.refreshExpiresIn")
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
		return nil, fmt.Errorf("存储 refresh_token 失败: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    config.GetInt("auth.expiresIn"),
	}, nil
}

func upsertUser(db *gorm.DB, tOpenID, nickname, avatar string) (*models.User, error) {
	var user models.User
	err := db.Where("t_openid = ?", tOpenID).First(&user).Error

	if err == nil {
		return &user, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	now := time.Now()
	user = models.User{
		OpenID:    generateID(),
		TOpenID:   tOpenID,
		Nickname:  nickname,
		Avatar:    avatar,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := db.Create(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

// VerifyAccessToken 验证 access_token 并解密身份信息
func VerifyAccessToken(tokenString string) (*Identity, error) {
	publicKey, err := getVerifyKey()
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("不支持的签名方法: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("无效的 token")
	}

	encryptedSub, ok := claims["sub"].(string)
	if !ok {
		return nil, errors.New("缺少 sub 声明")
	}

	identity, err := decryptIdentity(encryptedSub)
	if err != nil {
		return nil, fmt.Errorf("解密身份信息失败: %w", err)
	}

	return identity, nil
}

// RefreshTokens 刷新 token
func RefreshTokens(db *gorm.DB, refreshToken string) (*TokenPair, error) {
	var dbToken models.RefreshToken
	if err := db.Where("token = ?", refreshToken).First(&dbToken).Error; err != nil {
		return nil, errors.New("refresh_token 无效")
	}

	if dbToken.ExpiresAt.Before(time.Now()) {
		db.Delete(&dbToken)
		return nil, errors.New("refresh_token 已过期")
	}

	var user models.User
	if err := db.Where("openid = ?", dbToken.OpenID).First(&user).Error; err != nil {
		return nil, errors.New("用户不存在")
	}

	db.Delete(&dbToken)

	return GenerateTokenPair(db, user.TOpenID, user.Nickname, user.Avatar)
}

// RevokeRefreshToken 撤销 refresh_token
func RevokeRefreshToken(db *gorm.DB, refreshToken string) bool {
	result := db.Where("token = ?", refreshToken).Delete(&models.RefreshToken{})
	return result.RowsAffected > 0
}

// RevokeAllRefreshTokens 撤销用户所有 refresh_token
func RevokeAllRefreshTokens(db *gorm.DB, openid string) int64 {
	result := db.Where("openid = ?", openid).Delete(&models.RefreshToken{})
	return result.RowsAffected
}

// GetOpenIDFromToken 从 access_token 中获取 openid
func GetOpenIDFromToken(tokenString string) (string, error) {
	identity, err := VerifyAccessToken(tokenString)
	if err != nil {
		return "", err
	}
	return identity.GetOpenID(), nil
}

