#!/bin/bash
# 生成 SSL 证书脚本
# 用于本地开发环境的 HTTPS 支持

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
DOMAINS=(
    "auth.heliannuuthus.com"
    "hermes.heliannuuthus.com"
    "zwei.heliannuuthus.com"
    "atlas.heliannuuthus.com"
)

echo "🔐 生成 SSL 证书"
echo "=================="

# 检查 mkcert 是否安装
if ! command -v mkcert &> /dev/null; then
    echo "❌ mkcert 未安装"
    echo ""
    echo "请先安装 mkcert："
    echo "  macOS:   brew install mkcert"
    echo "  Linux:   参考 https://github.com/FiloSottile/mkcert"
    echo "  Windows: choco install mkcert"
    exit 1
fi

# 创建证书目录
mkdir -p "${CERTS_DIR}"
cd "${CERTS_DIR}"

# 检查是否已安装本地 CA
if ! mkcert -CAROOT &> /dev/null; then
    echo "📦 安装本地 CA..."
    mkcert -install
    echo "✅ 本地 CA 已安装"
else
    echo "✅ 本地 CA 已存在"
fi

# 检查证书是否已存在
if [ -f "fullchain.pem" ] && [ -f "privkey.pem" ]; then
    echo ""
    echo "⚠️  证书文件已存在："
    echo "  - fullchain.pem"
    echo "  - privkey.pem"
    echo ""
    read -p "是否重新生成？(y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "跳过证书生成"
        exit 0
    fi
    rm -f fullchain.pem privkey.pem *.pem
fi

# 询问证书类型
echo ""
echo "选择证书类型："
echo "  1) ECC (推荐，更小更快)"
echo "  2) RSA (默认，兼容性最好)"
read -p "请选择 [1/2] (默认: 1): " cert_type
cert_type=${cert_type:-1}

# 生成证书
echo ""
if [ "$cert_type" = "1" ]; then
    echo "🔑 生成 ECC 证书..."
    mkcert -ecdsa "${DOMAINS[@]}"
else
    echo "🔑 生成 RSA 证书..."
    mkcert "${DOMAINS[@]}"
fi

# 查找生成的文件
CERT_FILE=$(ls -t *.pem 2>/dev/null | grep -v key | head -1)
KEY_FILE=$(ls -t *-key.pem 2>/dev/null | head -1)

if [ -z "$CERT_FILE" ] || [ -z "$KEY_FILE" ]; then
    echo "❌ 证书生成失败"
    exit 1
fi

# 重命名文件
echo ""
echo "📝 重命名证书文件..."
mv "$CERT_FILE" fullchain.pem
mv "$KEY_FILE" privkey.pem

# 清理其他临时文件
rm -f *.pem 2>/dev/null || true

echo ""
echo "✅ 证书生成完成！"
echo ""
echo "证书文件："
echo "  - ${CERTS_DIR}/fullchain.pem"
echo "  - ${CERTS_DIR}/privkey.pem"
echo ""
echo "现在可以启动服务："
echo "  cd $(dirname "$SCRIPT_DIR")"
echo "  nerdctl compose up -d"
