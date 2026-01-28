package oss

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/logger"
)

var (
	client *oss.Client
	bucket *oss.Bucket
)

// getOSSEndpoint 根据环境变量获取 OSS endpoint（内网或公网）
func getOSSEndpoint() string {
	endpoint := config.GetString("oss.endpoint")
	if endpoint == "" {
		return ""
	}

	// 检查是否使用内网（优先级：环境变量 APP_ENV > 配置 app.env）
	// 环境变量 APP_ENV（Dockerfile 设置的 ENV APP_ENV）
	appEnv := config.V().GetString("APP_ENV")
	if appEnv == "" {
		// 尝试从配置读取
		appEnv = config.GetString("app.env")
	}

	useInternal := appEnv == "prod"

	if !useInternal {
		return endpoint
	}

	// 转换为内网 endpoint：oss-cn-beijing.aliyuncs.com -> oss-cn-beijing-internal.aliyuncs.com
	if strings.Contains(endpoint, "-internal.") {
		// 已经是内网地址，直接返回
		return endpoint
	}

	// 替换为内网地址
	internalEndpoint := strings.Replace(endpoint, ".aliyuncs.com", "-internal.aliyuncs.com", 1)
	logger.Infof("[OSS] 使用内网 endpoint: %s -> %s (Env: %s)", endpoint, internalEndpoint, appEnv)
	return internalEndpoint
}

// Init 初始化 OSS 客户端
func Init() error {
	endpoint := getOSSEndpoint()
	accessKeyID := config.GetString("oss.access-key-id")
	accessKeySecret := config.GetString("oss.access-key-secret")
	bucketName := config.GetString("oss.bucket")

	if endpoint == "" || accessKeyID == "" || accessKeySecret == "" || bucketName == "" {
		return fmt.Errorf("OSS 配置不完整，请检查 config.toml 中的 [oss] 配置")
	}

	var err error
	client, err = oss.New(endpoint, accessKeyID, accessKeySecret)
	if err != nil {
		return fmt.Errorf("初始化 OSS 客户端失败: %w", err)
	}

	bucket, err = client.Bucket(bucketName)
	if err != nil {
		return fmt.Errorf("获取 OSS Bucket 失败: %w", err)
	}

	logger.Infof("[OSS] 初始化成功 - Endpoint: %s, Bucket: %s, Internal: %v",
		endpoint, bucketName, strings.Contains(endpoint, "-internal"))
	return nil
}

// UploadImage 上传图片到 OSS（使用 prefix + filename，按日期组织）
// prefix: 文件路径前缀，如 "avatars", "images" 等
// filename: 文件名（不含路径），如果为空则自动生成
// reader: 文件内容读取器
// 返回: OSS 文件 URL
func UploadImage(prefix, filename string, reader io.Reader) (string, error) {
	if bucket == nil {
		return "", fmt.Errorf("OSS 客户端未初始化")
	}

	// 如果没有提供文件名，生成一个基于时间戳的唯一文件名
	if filename == "" {
		filename = fmt.Sprintf("%d.jpg", time.Now().UnixNano())
	}

	// 确保文件名有扩展名
	if filepath.Ext(filename) == "" {
		filename += ".jpg"
	}

	// 构建完整路径: prefix/yyyy/MM/dd/filename
	now := time.Now()
	objectKey := fmt.Sprintf("%s/%04d/%02d/%02d/%s", prefix, now.Year(), now.Month(), now.Day(), filename)

	return uploadByObjectKey(objectKey, reader)
}

// UploadImageByKey 上传图片到 OSS（使用完整的 objectKey，支持覆盖）
// objectKey: 完整的 OSS 对象键，如 "avatars/user123.jpg"
// reader: 文件内容读取器
// 返回: OSS 文件 URL
func UploadImageByKey(objectKey string, reader io.Reader) (string, error) {
	if bucket == nil {
		return "", fmt.Errorf("OSS 客户端未初始化")
	}

	// 确保 objectKey 不以 / 开头
	if len(objectKey) > 0 && objectKey[0] == '/' {
		objectKey = objectKey[1:]
	}

	return uploadByObjectKey(objectKey, reader)
}

// uploadByObjectKey 内部上传方法
func uploadByObjectKey(objectKey string, reader io.Reader) (string, error) {
	// 上传文件（如果已存在会自动覆盖）
	err := bucket.PutObject(objectKey, reader)
	if err != nil {
		return "", fmt.Errorf("上传文件到 OSS 失败: %w", err)
	}

	return buildObjectURL(objectKey), nil
}

// UploadImageWithSTS 使用 STS 凭证上传图片到 OSS（异步安全）
// objectKey: 完整的 OSS 对象键，如 "avatars/user123.jpg"
// reader: 文件内容读取器
// credentials: STS 临时凭证
// 返回: OSS 文件 URL
func UploadImageWithSTS(objectKey string, reader io.Reader, credentials *STSCredentials) (string, error) {
	// 确保 objectKey 不以 / 开头
	if len(objectKey) > 0 && objectKey[0] == '/' {
		objectKey = objectKey[1:]
	}

	endpoint := getOSSEndpoint()
	bucketName := config.GetString("oss.bucket")

	// 使用 STS 凭证创建临时客户端
	stsClient, err := oss.New(endpoint, credentials.AccessKeyID, credentials.AccessKeySecret,
		oss.SecurityToken(credentials.SecurityToken))
	if err != nil {
		return "", fmt.Errorf("创建 STS OSS 客户端失败: %w", err)
	}

	stsBucket, err := stsClient.Bucket(bucketName)
	if err != nil {
		return "", fmt.Errorf("获取 STS Bucket 失败: %w", err)
	}

	// 上传文件
	err = stsBucket.PutObject(objectKey, reader)
	if err != nil {
		return "", fmt.Errorf("使用 STS 凭证上传文件失败: %w", err)
	}

	url := buildObjectURL(objectKey)
	logger.Infof("[OSS STS] 上传成功 - Key: %s, URL: %s", objectKey, url)
	return url, nil
}

// buildObjectURL 构建对象 URL
func buildObjectURL(objectKey string) string {
	domain := config.GetString("oss.domain")
	if domain == "" {
		// 如果没有配置自定义域名，使用 OSS 默认域名
		endpoint := config.GetString("oss.endpoint")
		bucketName := config.GetString("oss.bucket")
		domain = fmt.Sprintf("https://%s.%s", bucketName, endpoint)
	} else {
		// 如果配置了自定义域名，确保有协议前缀
		if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
			domain = "https://" + domain
		}
	}

	// 确保 domain 不以 / 结尾
	if len(domain) > 0 && domain[len(domain)-1] == '/' {
		domain = domain[:len(domain)-1]
	}

	return fmt.Sprintf("%s/%s", domain, objectKey)
}

// BuildObjectURL 构建对象 URL（不实际上传，仅构建 URL）
func BuildObjectURL(objectKey string) string {
	return buildObjectURL(objectKey)
}

// DeleteImage 删除 OSS 中的图片
func DeleteImage(objectKey string) error {
	if bucket == nil {
		return fmt.Errorf("OSS 客户端未初始化")
	}

	err := bucket.DeleteObject(objectKey)
	if err != nil {
		return fmt.Errorf("删除 OSS 文件失败: %w", err)
	}

	logger.Infof("[OSS] 删除成功 - Key: %s", objectKey)
	return nil
}
