package handlers

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"choosy-backend/internal/auth"
	"choosy-backend/internal/logger"
	"choosy-backend/internal/models"
	"choosy-backend/internal/oss"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type UploadHandler struct {
	db *gorm.DB
}

func NewUploadHandler(db *gorm.DB) *UploadHandler {
	return &UploadHandler{db: db}
}

type UploadImageRequest struct {
	ObjectKey string `form:"object-key" binding:"omitempty,max=512"` // 完整的 OSS 对象键，如 "avatars/user123.jpg"（优先级高于 prefix）
	Prefix    string `form:"prefix" binding:"omitempty,max=64"`      // 文件路径前缀，如 "avatars", "images"（当 object-key 为空时使用）
}

type UploadImageResponse struct {
	URL string `json:"url"` // 上传后的图片 URL
}

// UploadImage 上传图片（通用 API）
// @Summary 上传图片到 OSS
// @Tags upload
// @Accept multipart/form-data
// @Produce json
// @Security Bearer
// @Param object-key formData string false "完整的 OSS 对象键，如 avatars/user123.jpg（优先级高于 prefix）"
// @Param prefix formData string false "文件路径前缀，如 avatars, images（当 object-key 为空时使用）"
// @Param file formData file true "图片文件"
// @Success 200 {object} UploadImageResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/upload/image [post]
func (h *UploadHandler) UploadImage(c *gin.Context) {
	// 检查认证（可选，如果需要登录才能上传则取消注释）
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
		return
	}

	identity := user.(*auth.Identity)

	// 解析表单
	var req UploadImageRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": fmt.Sprintf("参数错误: %v", err)})
		return
	}

	// 获取上传的文件
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "请选择要上传的文件"})
		return
	}

	// 验证文件类型（只允许图片）
	contentType := file.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "只支持上传图片文件"})
		return
	}

	// 验证文件大小（限制 5MB）
	if file.Size > 5*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "图片大小不能超过 5MB"})
		return
	}

	// 确定 object-key
	objectKey := req.ObjectKey
	if objectKey == "" {
		prefix := req.Prefix
		if prefix == "" {
			prefix = "images"
		}
		// 使用 prefix + filename（按日期组织）
		now := time.Now()
		objectKey = fmt.Sprintf("%s/%04d/%02d/%02d/%s", prefix, now.Year(), now.Month(), now.Day(), file.Filename)
	}

	// 构建预期的 OSS URL（立即返回给前端）
	expectedURL := oss.BuildObjectURL(objectKey)

	// 读取文件内容到内存（用于异步上传）
	fileSrc, err := file.Open()
	if err != nil {
		logger.Errorf("[Upload] 打开文件失败 - OpenID: %s, Error: %v", identity.GetOpenID(), err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "读取文件失败"})
		return
	}
	defer fileSrc.Close()

	fileData, err := io.ReadAll(fileSrc)
	if err != nil {
		logger.Errorf("[Upload] 读取文件失败 - OpenID: %s, Error: %v", identity.GetOpenID(), err)
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "读取文件失败"})
		return
	}

	// 立即返回成功响应（前端不需要等待 OSS 上传完成）
	c.JSON(http.StatusOK, UploadImageResponse{URL: expectedURL})

	// 异步上传到 OSS（使用 STS 凭证）
	go h.uploadToOSSAsync(identity.GetOpenID(), objectKey, bytes.NewReader(fileData))
}

// uploadToOSSAsync 异步上传文件到 OSS（优先使用 STS 凭证，失败则回退到主账号凭证）
func (h *UploadHandler) uploadToOSSAsync(openid, objectKey string, reader io.Reader) {
	logger.Infof("[Upload] 开始异步上传 - OpenID: %s, ObjectKey: %s", openid, objectKey)

	// 尝试生成 STS 凭证（如果 STS 已配置）
	credentials, err := oss.GenerateSTSCredentials(objectKey, 3600)
	if err != nil {
		// STS 未配置或失败，使用主账号凭证
		logger.Warnf("[Upload] STS 不可用，使用主账号凭证上传 - OpenID: %s, ObjectKey: %s, Error: %v", openid, objectKey, err)
		uploadURL, err := oss.UploadImageByKey(objectKey, reader)
		if err != nil {
			logger.Errorf("[Upload] 异步上传失败（主账号凭证） - OpenID: %s, ObjectKey: %s, Error: %v", openid, objectKey, err)
			return
		}
		logger.Infof("[Upload] 异步上传成功（主账号凭证） - OpenID: %s, URL: %s", openid, uploadURL)

		// 如果是头像上传，更新数据库
		h.updateAvatarIfNeeded(openid, objectKey, uploadURL)
		return
	}

	// 使用 STS 凭证上传
	uploadURL, err := oss.UploadImageWithSTS(objectKey, reader, credentials)
	if err != nil {
		logger.Errorf("[Upload] STS 上传失败，回退到主账号凭证 - OpenID: %s, ObjectKey: %s, Error: %v", openid, objectKey, err)
		// 回退到主账号凭证
		uploadURL, err := oss.UploadImageByKey(objectKey, reader)
		if err != nil {
			logger.Errorf("[Upload] 异步上传失败（回退方案） - OpenID: %s, ObjectKey: %s, Error: %v", openid, objectKey, err)
			return
		}
		logger.Infof("[Upload] 异步上传成功（回退方案） - OpenID: %s, URL: %s", openid, uploadURL)
		h.updateAvatarIfNeeded(openid, objectKey, uploadURL)
		return
	}

	logger.Infof("[Upload] 异步上传成功（STS 凭证） - OpenID: %s, URL: %s", openid, uploadURL)
	h.updateAvatarIfNeeded(openid, objectKey, uploadURL)
}

// updateAvatarIfNeeded 如果是头像上传，更新用户头像
func (h *UploadHandler) updateAvatarIfNeeded(openid, objectKey, uploadURL string) {
	// 如果是头像上传（路径为 avatars/{openid}.jpg），自动更新用户头像
	if strings.HasPrefix(objectKey, "avatars/") && strings.HasSuffix(objectKey, ".jpg") {
		expectedOpenID := strings.TrimPrefix(objectKey, "avatars/")
		expectedOpenID = strings.TrimSuffix(expectedOpenID, ".jpg")
		if expectedOpenID == openid {
			// 更新用户头像
			if err := h.db.Model(&models.User{}).Where("openid = ?", openid).Update("avatar", uploadURL).Error; err != nil {
				logger.Errorf("[Upload] 更新用户头像失败 - OpenID: %s, URL: %s, Error: %v", openid, uploadURL, err)
			} else {
				logger.Infof("[Upload] 用户头像已更新 - OpenID: %s, URL: %s", openid, uploadURL)
			}
		}
	}
}
