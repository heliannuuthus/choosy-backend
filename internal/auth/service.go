package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"zwei-backend/internal/config"
	"zwei-backend/internal/idp/alipay"
	"zwei-backend/internal/idp/tt"
	"zwei-backend/internal/idp/wechat"
	"zwei-backend/internal/logger"
	"zwei-backend/internal/models"

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

// Login 统一登录入口
// idp: 身份提供方，如 wechat:mp, tt:mp, alipay:mp
// code: 平台返回的授权码
func (s *Service) Login(idp, code string) (*TokenPair, error) {
	logger.Infof("[Auth] 开始登录流程 - IDP: %s", idp)

	var tOpenID, unionID string
	var err error

	switch idp {
	case IDPWechatMP:
		client := wechat.NewClient()
		result, err := client.Code2Session(code)
		if err != nil {
			return nil, fmt.Errorf("微信登录失败: %w", err)
		}
		tOpenID = result.OpenID
		unionID = result.UnionID

	case IDPTTMP:
		client := tt.NewClient()
		result, err := client.Code2Session(code)
		if err != nil {
			return nil, fmt.Errorf("抖音登录失败: %w", err)
		}
		tOpenID = result.OpenID
		unionID = result.UnionID

	case IDPAlipayMP:
		client := alipay.NewClient()
		result, err := client.Code2Session(code)
		if err != nil {
			return nil, fmt.Errorf("支付宝登录失败: %w", err)
		}
		tOpenID = result.OpenID
		unionID = result.UnionID

	default:
		return nil, fmt.Errorf("不支持的平台: %s", idp)
	}

	// 生成默认昵称和头像
	nickname := generateRandomNickname()
	avatar := generateRandomAvatar(tOpenID)

	// 查找或创建用户
	user, err := s.selectOrCreateUser(idp, tOpenID, unionID, nickname, avatar)
	if err != nil {
		return nil, fmt.Errorf("用户管理失败: %w", err)
	}

	// 生成 token
	return s.generateTokenPair(user, idp)
}

// selectOrCreateUser 查找或创建用户（支持 unionid 关联）
func (s *Service) selectOrCreateUser(idp, tOpenID, unionID, nickname, avatar string) (*models.User, error) {
	logger.Infof("[Auth] 开始查询/创建用户 - IDP: %s, T_OpenID: %s, UnionID: %s", idp, tOpenID, unionID)

	now := time.Now()

	// 1. 先查当前 idp + t_openid 是否存在
	var identity models.UserIdentity
	err := s.db.Where("idp = ? AND t_openid = ?", idp, tOpenID).First(&identity).Error

	if err == nil {
		// 找到了，直接查用户
		var user models.User
		if err := s.db.Where("openid = ?", identity.OpenID).First(&user).Error; err != nil {
			logger.Errorf("[Auth] 用户身份存在但用户不存在 - OpenID: %s, Error: %v", identity.OpenID, err)
			return nil, err
		}

		// 更新最后登录时间
		s.db.Model(&user).Update("last_login_at", now)

		logger.Infof("[Auth] 找到现有用户 - OpenID: %s, IDP: %s, Nickname: %s", user.OpenID, idp, user.Nickname)
		return &user, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Errorf("[Auth] 查询用户身份失败 - IDP: %s, T_OpenID: %s, Error: %v", idp, tOpenID, err)
		return nil, err
	}

	// 2. 没找到，如果有 unionid，尝试通过 unionid 关联
	var existingOpenID string
	if unionID != "" {
		unionIDP := getUnionIDP(idp)
		var unionIdentity models.UserIdentity
		err := s.db.Where("idp = ? AND t_openid = ?", unionIDP, unionID).First(&unionIdentity).Error
		if err == nil {
			existingOpenID = unionIdentity.OpenID
			logger.Infof("[Auth] 通过 UnionID 找到已有用户 - OpenID: %s, UnionIDP: %s", existingOpenID, unionIDP)
		}
	}

	// 3. 开始事务：创建用户或绑定身份
	var user models.User
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if existingOpenID != "" {
			// 已有用户，只需绑定新身份
			if err := tx.Where("openid = ?", existingOpenID).First(&user).Error; err != nil {
				return err
			}
		} else {
			// 创建新用户
			user = models.User{
				OpenID:      GenerateID(),
				Nickname:    nickname,
				Avatar:      avatar,
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
			IDP:       idp,
			TOpenID:   tOpenID,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := tx.Create(&newIdentity).Error; err != nil {
			return err
		}
		logger.Infof("[Auth] 绑定身份 - OpenID: %s, IDP: %s, T_OpenID: %s", user.OpenID, idp, tOpenID)

		// 如果有 unionid 且之前没有记录，也插入
		if unionID != "" && existingOpenID == "" {
			unionIDP := getUnionIDP(idp)
			unionIdentity := models.UserIdentity{
				OpenID:    user.OpenID,
				IDP:       unionIDP,
				TOpenID:   unionID,
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := tx.Create(&unionIdentity).Error; err != nil {
				return err
			}
			logger.Infof("[Auth] 绑定 UnionID - OpenID: %s, IDP: %s, UnionID: %s", user.OpenID, unionIDP, unionID)
		}

		return nil
	})

	if err != nil {
		logger.Errorf("[Auth] 创建用户/绑定身份失败 - Error: %v", err)
		return nil, err
	}

	// 更新最后登录时间（如果是已有用户绑定新身份）
	if existingOpenID != "" {
		s.db.Model(&user).Update("last_login_at", now)
	}

	return &user, nil
}

// generateTokenPair 生成 token 对
func (s *Service) generateTokenPair(user *models.User, idp string) (*TokenPair, error) {
	logger.Infof("[Auth] 开始生成 Token 对 - OpenID: %s, IDP: %s", user.OpenID, idp)

	now := time.Now()

	identity := &Identity{
		OpenID:   user.OpenID,
		Nickname: user.Nickname,
		Avatar:   user.Avatar,
	}

	accessToken, err := CreateAccessToken(identity, idp)
	if err != nil {
		logger.Errorf("[Auth] 生成 Access Token 失败 - OpenID: %s, Error: %v", user.OpenID, err)
		return nil, fmt.Errorf("生成 access_token 失败: %w", err)
	}

	refreshToken := GenerateRefreshToken()
	refreshExpiresIn := config.GetInt("auth.refresh-expires-in")
	expiresAt := now.Add(time.Duration(refreshExpiresIn) * 24 * time.Hour)

	CleanupOldRefreshTokens(s.db, user.OpenID)

	dbToken := models.RefreshToken{
		OpenID:    user.OpenID,
		Token:     refreshToken,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.db.Create(&dbToken).Error; err != nil {
		logger.Errorf("[Auth] 存储 Refresh Token 失败 - OpenID: %s, Error: %v", user.OpenID, err)
		return nil, fmt.Errorf("存储 refresh_token 失败: %w", err)
	}

	logger.Infof("[Auth] Token 对生成成功 - OpenID: %s, Aud: %s:%s, ExpiresIn: %ds",
		user.OpenID, config.GetString("auth.issuer"), idp, config.GetInt("auth.expires-in"))

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    config.GetInt("auth.expires-in"),
	}, nil
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

// generateRandomNickname 生成随机昵称
func generateRandomNickname() string {
	adjectives := []string{"快乐的", "聪明的", "勇敢的", "温柔的", "活泼的", "安静的", "优雅的", "幽默的"}
	nouns := []string{"小猫", "小狗", "小鸟", "小鱼", "小兔", "小熊", "小鹿", "小羊"}

	adjIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	nounIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))

	return adjectives[adjIndex.Int64()] + nouns[nounIndex.Int64()] + fmt.Sprintf("%04d", time.Now().Unix()%10000)
}

// generateRandomAvatar 生成随机头像 URL
func generateRandomAvatar(seed string) string {
	// 使用 seed 生成一致的随机数
	hash := 0
	for _, c := range seed {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}

	avatarIndex := hash % 10
	return fmt.Sprintf("https://api.dicebear.com/7.x/avataaars/svg?seed=%s&size=200", fmt.Sprintf("user%d", avatarIndex))
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
