package cache

import (
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// 类型别名，直接使用 hermes models 的类型
type (
	Application = models.ApplicationWithKey
	Service     = models.ServiceWithKey
	Domain      = models.DomainWithKey
)
