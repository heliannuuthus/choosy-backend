package handlers

import (
	"net/http"

	"choosy-backend/internal/auth"
	"choosy-backend/internal/logger"
	"choosy-backend/internal/preference"
	"choosy-backend/internal/tag"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// PreferenceHandler 用户偏好处理器
type PreferenceHandler struct {
	service *preference.Service
}

// NewPreferenceHandler 创建用户偏好处理器
func NewPreferenceHandler(db *gorm.DB) *PreferenceHandler {
	return &PreferenceHandler{
		service: preference.NewService(db),
	}
}

// GetOptions 获取所有偏好选项
// @Summary 获取所有偏好选项
// @Description 获取口味、忌口、过敏的所有可选选项（从缓存索引获取，性能最优）
// @Tags preference
// @Produce json
// @Success 200 {object} preference.OptionsResponse
// @Failure 500 {object} map[string]string
// @Router /api/preferences [get]
func (h *PreferenceHandler) GetOptions(c *gin.Context) {
	options, err := h.service.GetOptions()
	if err != nil {
		logger.Error("获取偏好选项失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取偏好选项失败"})
		return
	}

	c.JSON(http.StatusOK, options)
}

// GetUserPreferences 获取用户偏好
// @Summary 获取用户偏好
// @Description 获取当前用户的偏好设置（包含选中状态）
// @Tags preference
// @Produce json
// @Security BearerAuth
// @Success 200 {object} preference.UserPreferencesResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/user/preference [get]
func (h *PreferenceHandler) GetUserPreferences(c *gin.Context) {
	// 获取当前用户
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权"})
		return
	}

	identity := user.(*auth.Identity)
	prefs, err := h.service.GetUserPreferences(identity.OpenID)
	if err != nil {
		logger.Error("获取用户偏好失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户偏好失败"})
		return
	}

	c.JSON(http.StatusOK, prefs)
}

// UpdateUserPreferences 更新用户偏好
// @Summary 更新用户偏好
// @Description 更新当前用户的偏好设置（全量替换）
// @Tags preference
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body preference.UpdatePreferencesRequest true "偏好设置"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/user/preference [put]
func (h *PreferenceHandler) UpdateUserPreferences(c *gin.Context) {
	// 获取当前用户
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权"})
		return
	}

	identity := user.(*auth.Identity)
	var req preference.UpdatePreferencesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误: " + err.Error()})
		return
	}

	// 验证标签值（从 service 中获取 tagService）
	tagService := tag.NewService(h.service.GetDB())
	if err := req.Validate(tagService); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新偏好
	if err := h.service.UpdateUserPreferences(identity.OpenID, &req); err != nil {
		logger.Error("更新用户偏好失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户偏好失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}
