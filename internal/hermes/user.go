package hermes

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/kms"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// UserService 用户服务（连接数据库）
type UserService struct {
	db *gorm.DB
}

// NewUserService 创建用户服务
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db}
}

// FindByOpenID 根据 OpenID 查找用户
func (s *UserService) FindByOpenID(ctx context.Context, openID string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("openid = ?", openID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByIdentity 根据 IDP + ProviderID 查找用户
func (s *UserService) FindByIdentity(ctx context.Context, idp, providerID string) (*models.User, error) {
	var identity models.UserIdentity
	if err := s.db.WithContext(ctx).Where("idp = ? AND t_openid = ?", idp, providerID).First(&identity).Error; err != nil {
		return nil, err
	}

	return s.FindByOpenID(ctx, identity.OpenID)
}

// Create 创建用户
func (s *UserService) Create(ctx context.Context, user *models.User) error {
	return s.db.WithContext(ctx).Create(user).Error
}

// CreateWithIdentity 创建用户及身份关联（事务）
func (s *UserService) CreateWithIdentity(ctx context.Context, user *models.User, identity *models.UserIdentity) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return fmt.Errorf("创建用户失败: %w", err)
		}

		identity.OpenID = user.OpenID
		if err := tx.Create(identity).Error; err != nil {
			return fmt.Errorf("创建身份关联失败: %w", err)
		}

		return nil
	})
}

// Update 更新用户
func (s *UserService) Update(ctx context.Context, openID string, updates map[string]any) error {
	return s.db.WithContext(ctx).Model(&models.User{}).Where("openid = ?", openID).Updates(updates).Error
}

// UpdateLastLogin 更新最后登录时间
func (s *UserService) UpdateLastLogin(ctx context.Context, openID string) error {
	return s.Update(ctx, openID, map[string]any{"last_login_at": time.Now()})
}

// AddIdentity 添加身份关联
func (s *UserService) AddIdentity(ctx context.Context, identity *models.UserIdentity) error {
	return s.db.WithContext(ctx).Create(identity).Error
}

// GetIdentities 获取用户所有身份关联
func (s *UserService) GetIdentities(ctx context.Context, openID string) ([]models.UserIdentity, error) {
	var identities []models.UserIdentity
	if err := s.db.WithContext(ctx).Where("openid = ?", openID).Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

// GetUserWithDecrypted 获取解密后的用户（解密手机号）
func (s *UserService) GetUserWithDecrypted(ctx context.Context, openID string) (*models.UserWithDecrypted, error) {
	user, err := s.FindByOpenID(ctx, openID)
	if err != nil {
		return nil, err
	}

	result := &models.UserWithDecrypted{
		User: *user,
	}

	// 解密手机号
	if user.PhoneCipher != nil && *user.PhoneCipher != "" {
		phone, err := kms.DecryptPhone(*user.PhoneCipher, user.OpenID)
		if err != nil {
			logger.Warnf("[UserService] 解密手机号失败: %v", err)
		} else {
			result.Phone = phone
		}
	}

	return result, nil
}

// GetUserWithDecryptedByIdentity 根据身份获取解密后的用户
func (s *UserService) GetUserWithDecryptedByIdentity(ctx context.Context, idp, providerID string) (*models.UserWithDecrypted, error) {
	user, err := s.FindByIdentity(ctx, idp, providerID)
	if err != nil {
		return nil, err
	}

	return s.GetUserWithDecrypted(ctx, user.OpenID)
}

// FindOrCreate 查找或创建用户
// 返回用户和是否为新创建
func (s *UserService) FindOrCreate(ctx context.Context, req *models.FindOrCreateUserRequest) (*models.UserWithDecrypted, bool, error) {
	// 1. 尝试通过身份查找
	user, err := s.FindByIdentity(ctx, req.IDP, req.ProviderID)
	if err == nil {
		// 找到用户，更新最后登录时间
		if err := s.UpdateLastLogin(ctx, user.OpenID); err != nil {
			logger.Warnf("[UserService] update last login failed: %v", err)
		}
		logger.Infof("[UserService] 找到已有用户 - OpenID: %s, IDP: %s", user.OpenID, req.IDP)

		result, err := s.GetUserWithDecrypted(ctx, user.OpenID)
		return result, false, err
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, fmt.Errorf("查找用户失败: %w", err)
	}

	// 2. 创建新用户
	now := time.Now()
	newUser := &models.User{
		OpenID:      models.GenerateOpenID(),
		Domain:      req.Domain,
		Name:        generateRandomName(),
		Picture:     generateRandomAvatar(req.ProviderID),
		LastLoginAt: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	identity := &models.UserIdentity{
		OpenID:    newUser.OpenID,
		IDP:       req.IDP,
		TOpenID:   req.ProviderID,
		UnionID:   req.UnionID,
		RawData:   req.RawData,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.CreateWithIdentity(ctx, newUser, identity); err != nil {
		return nil, false, err
	}

	logger.Infof("[UserService] 创建新用户 - OpenID: %s, IDP: %s", newUser.OpenID, req.IDP)

	result := &models.UserWithDecrypted{
		User: *newUser,
	}

	return result, true, nil
}

// generateRandomName 生成随机昵称
func generateRandomName() string {
	adjectives := []string{"快乐的", "聪明的", "勇敢的", "温柔的", "活泼的", "安静的", "优雅的", "幽默的"}
	nouns := []string{"小猫", "小狗", "小鸟", "小鱼", "小兔", "小熊", "小鹿", "小羊"}

	adjIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	if err != nil {
		panic(fmt.Sprintf("generate random name failed: %v", err))
	}
	nounIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))
	if err != nil {
		panic(fmt.Sprintf("generate random name failed: %v", err))
	}

	return adjectives[adjIndex.Int64()] + nouns[nounIndex.Int64()] + fmt.Sprintf("%04d", time.Now().Unix()%10000)
}

// generateRandomAvatar 生成随机头像
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
