package authenticate

import (
	"context"

	"github.com/heliannuuthus/helios/pkg/logger"
)

// EmailSender 邮件发送接口
type EmailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// NoopSender 空实现（开发测试用，打印到日志）
type NoopSender struct{}

// NewNoopSender 创建空实现发送器
func NewNoopSender() *NoopSender {
	return &NoopSender{}
}

// Send 发送邮件（仅打印日志）
func (s *NoopSender) Send(ctx context.Context, to, subject, body string) error {
	logger.Infof("[NoopSender] 模拟发送邮件 - To: %s, Subject: %s, Body: %s", to, subject, body)
	return nil
}
