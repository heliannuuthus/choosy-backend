package utils

import (
	"crypto/rand"
	"math/big"
)

// Base62 字符集
const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// GenerateID 生成 base62 编码的随机 ID
// length: 生成的 ID 长度（默认 12，约 62^12 ≈ 3.2×10^21 种可能）
func GenerateID(length int) string {
	if length <= 0 {
		length = 12
	}

	// 计算需要的随机字节数
	// 62^length 需要 log2(62^length) = length * log2(62) ≈ length * 5.95 bits
	// 向上取整到字节
	byteLen := (length*6 + 7) / 8

	// 生成随机字节
	randomBytes := make([]byte, byteLen)
	_, _ = rand.Read(randomBytes)

	// 转换为大整数
	num := new(big.Int).SetBytes(randomBytes)

	// 转换为 base62
	base := big.NewInt(62)
	result := make([]byte, length)

	for i := length - 1; i >= 0; i-- {
		mod := new(big.Int)
		num.DivMod(num, base, mod)
		result[i] = base62Chars[mod.Int64()]
	}

	return string(result)
}

// GenerateRecipeID 生成菜谱 ID（22位 Base62）
func GenerateRecipeID() string {
	return GenerateID(22)
}
