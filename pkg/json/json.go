// Package json 提供高性能 JSON 序列化/反序列化
// 使用 goccy/go-json 替代标准库，性能提升约 2-3 倍
package json

import (
	"io"

	gojson "github.com/goccy/go-json"
)

// Marshal 序列化为 JSON
func Marshal(v any) ([]byte, error) {
	return gojson.Marshal(v)
}

// MarshalIndent 序列化为格式化的 JSON
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return gojson.MarshalIndent(v, prefix, indent)
}

// Unmarshal 反序列化 JSON
func Unmarshal(data []byte, v any) error {
	return gojson.Unmarshal(data, v)
}

// NewEncoder 创建 JSON 编码器
func NewEncoder(w io.Writer) *gojson.Encoder {
	return gojson.NewEncoder(w)
}

// NewDecoder 创建 JSON 解码器
func NewDecoder(r io.Reader) *gojson.Decoder {
	return gojson.NewDecoder(r)
}

// Valid 检查是否为有效的 JSON
func Valid(data []byte) bool {
	return gojson.Valid(data)
}
