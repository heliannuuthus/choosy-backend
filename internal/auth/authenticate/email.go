package authenticate

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/heliannuuthus/helios/internal/auth/cache"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// EmailAuthenticator 邮箱验证码认证器
type EmailAuthenticator struct {
	cache  *cache.Manager
	sender EmailSender
	otpTTL time.Duration
}

// NewEmailAuthenticator 创建邮箱认证器
func NewEmailAuthenticator(cache *cache.Manager, sender EmailSender) *EmailAuthenticator {
	return &EmailAuthenticator{
		cache:  cache,
		sender: sender,
		otpTTL: 5 * time.Minute,
	}
}

// Type 返回认证器类型
func (*EmailAuthenticator) Type() AuthType {
	return AuthTypeEmail
}

// Supports 判断是否支持该 connection
func (*EmailAuthenticator) Supports(connection string) bool {
	return connection == "email"
}

// Authenticate 执行认证（验证验证码）
func (a *EmailAuthenticator) Authenticate(ctx context.Context, _ string, data map[string]any) (*AuthResult, error) {
	// 获取 email 和 code
	email, ok := data["email"].(string)
	if !ok || email == "" {
		return nil, errors.New("email is required")
	}

	code, ok := data["code"].(string)
	if !ok || code == "" {
		return nil, errors.New("code is required")
	}

	// 验证验证码
	if err := a.cache.VerifyOTP(ctx, a.otpKey(email), code); err != nil {
		return nil, fmt.Errorf("invalid or expired code: %w", err)
	}

	logger.Infof("[EmailAuth] 验证成功 - Email: %s", email)

	return &AuthResult{
		ProviderID: email, // 邮箱作为 ProviderID
	}, nil
}

// SendCode 发送验证码
func (a *EmailAuthenticator) SendCode(ctx context.Context, email string) error {
	// 生成 6 位数字验证码
	code, err := generateOTP(6)
	if err != nil {
		return fmt.Errorf("generate otp failed: %w", err)
	}

	// 保存到缓存
	if err := a.cache.SaveOTP(ctx, a.otpKey(email), code, a.otpTTL); err != nil {
		return fmt.Errorf("save otp failed: %w", err)
	}

	// 发送邮件
	subject := "验证码"
	body := fmt.Sprintf("您的验证码是：%s，有效期 %d 分钟。", code, int(a.otpTTL.Minutes()))
	if err := a.sender.Send(ctx, email, subject, body); err != nil {
		return fmt.Errorf("send email failed: %w", err)
	}

	logger.Infof("[EmailAuth] 发送验证码成功 - Email: %s", email)
	return nil
}

// otpKey 生成 OTP 缓存 key
func (a *EmailAuthenticator) otpKey(email string) string {
	return "email:" + email
}

// generateOTP 生成指定位数的数字验证码
func generateOTP(length int) (string, error) {
	digits := "0123456789"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		result[i] = digits[idx.Int64()]
	}
	return string(result), nil
}
