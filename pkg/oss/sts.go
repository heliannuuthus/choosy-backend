package oss

import (
	"fmt"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

var (
	stsClient *sts.Client
)

// InitSTS 初始化 STS 客户端
func InitSTS() error {
	accessKeyID := config.GetString("oss.access-key-id")
	accessKeySecret := config.GetString("oss.access-key-secret")
	region := config.GetString("oss.region")

	if accessKeyID == "" || accessKeySecret == "" {
		return fmt.Errorf("OSS AccessKey 未配置")
	}

	// 如果没有配置 region，从 endpoint 提取
	if region == "" {
		endpoint := config.GetString("oss.endpoint")
		// 从 oss-cn-beijing.aliyuncs.com 提取 cn-beijing
		if len(endpoint) > 4 && endpoint[:4] == "oss-" {
			region = endpoint[4:]
			if idx := len(region) - len(".aliyuncs.com"); idx > 0 {
				region = region[:idx]
			}
		} else {
			region = "cn-beijing" // 默认值
		}
	}

	var err error
	stsClient, err = sts.NewClientWithAccessKey(region, accessKeyID, accessKeySecret)
	if err != nil {
		return fmt.Errorf("初始化 STS 客户端失败: %w", err)
	}

	logger.Infof("[OSS STS] 初始化成功 - Region: %s", region)
	return nil
}

// STSCredentials STS 临时凭证
type STSCredentials struct {
	AccessKeyID     string    `json:"accessKeyId"`
	AccessKeySecret string    `json:"accessKeySecret"`
	SecurityToken   string    `json:"securityToken"`
	Expiration      time.Time `json:"expiration"`
}

// GenerateSTSCredentials 生成 STS 临时凭证
// objectKey: 允许上传的 OSS 对象键，如 "avatars/user123.jpg"
// durationSeconds: 凭证有效期（秒），默认 3600（1小时）
func GenerateSTSCredentials(objectKey string, durationSeconds int64) (*STSCredentials, error) {
	if stsClient == nil {
		return nil, fmt.Errorf("STS 客户端未初始化")
	}

	if durationSeconds <= 0 {
		durationSeconds = 3600 // 默认 1 小时
	}
	if durationSeconds > 3600 {
		durationSeconds = 3600 // 最大 1 小时
	}

	roleArn := config.GetString("oss.role-arn")
	if roleArn == "" {
		return nil, fmt.Errorf("OSS STS Role ARN 未配置")
	}

	bucketName := config.GetString("oss.bucket")
	if bucketName == "" {
		return nil, fmt.Errorf("OSS Bucket 未配置")
	}

	// 构建权限策略
	policy := buildPolicy(bucketName, objectKey)

	request := sts.CreateAssumeRoleRequest()
	request.Scheme = "https"
	request.RoleArn = roleArn
	request.RoleSessionName = fmt.Sprintf("upload-%d", time.Now().Unix())
	request.DurationSeconds = requests.NewInteger(int(durationSeconds))
	request.Policy = policy

	response, err := stsClient.AssumeRole(request)
	if err != nil {
		logger.Errorf("[OSS STS] 生成凭证失败 - ObjectKey: %s, Error: %v", objectKey, err)
		return nil, fmt.Errorf("生成 STS 凭证失败: %w", err)
	}

	expiration, err := time.Parse(time.RFC3339, response.Credentials.Expiration)
	if err != nil {
		logger.Errorf("[OSS STS] 解析过期时间失败 - Expiration: %s, Error: %v", response.Credentials.Expiration, err)
		expiration = time.Now().Add(time.Duration(durationSeconds) * time.Second)
	}

	credentials := &STSCredentials{
		AccessKeyID:     response.Credentials.AccessKeyId,
		AccessKeySecret: response.Credentials.AccessKeySecret,
		SecurityToken:   response.Credentials.SecurityToken,
		Expiration:      expiration,
	}

	logger.Infof("[OSS STS] 凭证生成成功 - ObjectKey: %s, Expiration: %s", objectKey, expiration.Format(time.RFC3339))
	return credentials, nil
}

// buildPolicy 构建权限策略（仅允许上传到指定路径）
func buildPolicy(bucketName, objectKey string) string {
	// 确保 objectKey 不以 / 开头
	if len(objectKey) > 0 && objectKey[0] == '/' {
		objectKey = objectKey[1:]
	}

	// 构建符合阿里云 STS 策略格式的 JSON
	// 转义 Resource 中的特殊字符（JSON 字符串转义）
	resource := fmt.Sprintf("acs:oss:*:*:%s/%s", bucketName, objectKey)
	resourceEscaped := strings.ReplaceAll(resource, `\`, `\\`)
	resourceEscaped = strings.ReplaceAll(resourceEscaped, `"`, `\"`)

	// 构建策略 JSON（紧凑格式，符合阿里云要求）
	policyJSON := fmt.Sprintf(`{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:PutObject"],"Resource":["%s"]}]}`, resourceEscaped)

	// 验证 JSON 格式
	var testPolicy map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &testPolicy); err != nil {
		logger.Errorf("[OSS STS] 策略 JSON 格式验证失败 - Error: %v, Policy: %s", err, policyJSON)
		return "{}"
	}

	// 记录生成的策略（用于调试）
	logger.Debugf("[OSS STS] 生成的策略 - ObjectKey: %s, Resource: %s, Policy: %s", objectKey, resource, policyJSON)

	return policyJSON
}
