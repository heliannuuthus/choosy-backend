#!/bin/bash
# 检查证书和浏览器访问问题的脚本

set -e

echo "🔍 证书和浏览器访问诊断"
echo "========================"
echo ""

# 1. 检查证书文件
echo "1. 检查证书文件..."
CERTS_DIR="$(dirname "$0")/certs"
if [ -f "${CERTS_DIR}/fullchain.pem" ] && [ -f "${CERTS_DIR}/privkey.pem" ]; then
    echo "   ✅ 证书文件存在"
    
    # 检查证书有效期
    echo "   证书信息："
    openssl x509 -in "${CERTS_DIR}/fullchain.pem" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/      /'
else
    echo "   ❌ 证书文件不存在"
    echo "   请运行: cd environments && ./generate-certs.sh"
    exit 1
fi

echo ""

# 2. 检查服务状态
echo "2. 检查服务状态..."
if nerdctl compose ps | grep -q "helios-https-proxy.*running"; then
    echo "   ✅ https-proxy 运行中"
else
    echo "   ❌ https-proxy 未运行"
    echo "   请运行: nerdctl compose up -d"
fi

if nerdctl compose ps | grep -q "helios-gateway.*running"; then
    echo "   ✅ gateway 运行中"
else
    echo "   ❌ gateway 未运行"
fi

echo ""

# 3. 测试 HTTPS 连接
echo "3. 测试 HTTPS 连接..."
if curl -k -s -o /dev/null -w "%{http_code}" https://atlas.heliannuuthus.com | grep -q "200"; then
    echo "   ✅ HTTPS 连接正常"
else
    echo "   ❌ HTTPS 连接失败"
fi

echo ""

# 4. 检查 mkcert CA
echo "4. 检查 mkcert CA..."
if command -v mkcert >/dev/null 2>&1; then
    CA_ROOT=$(mkcert -CAROOT 2>/dev/null || echo "")
    if [ -n "$CA_ROOT" ] && [ -f "${CA_ROOT}/rootCA.pem" ]; then
        echo "   ✅ mkcert CA 已安装"
        echo "   CA 位置: ${CA_ROOT}"
    else
        echo "   ⚠️  mkcert CA 未找到"
    fi
else
    echo "   ⚠️  mkcert 未安装或不在 PATH"
fi

echo ""

# 5. 浏览器访问建议
echo "5. 浏览器访问问题排查："
echo ""
echo "   📌 如果使用 Windows Chrome："
echo "      1. 在 Windows PowerShell 中运行: mkcert -install"
echo "      2. 清除浏览器缓存（Ctrl+Shift+Delete）"
echo "      3. 访问 chrome://net-internals/#hsts"
echo "      4. 删除 atlas.heliannuuthus.com 的 HSTS 策略"
echo ""
echo "   📌 如果使用 WSL 内 Chrome："
echo "      1. 确认 mkcert -install 已在 WSL 内运行"
echo "      2. 检查证书信任存储"
echo ""
echo "   📌 通用解决方案："
echo "      1. 使用隐私模式/无痕模式访问"
echo "      2. 清除浏览器缓存和 HSTS"
echo "      3. 检查浏览器控制台错误信息（F12）"
echo ""

# 6. 测试从容器访问
echo "6. 测试从 gateway 容器访问前端..."
if nerdctl exec helios-gateway wget -q -O- --timeout=2 --header="Host: atlas.heliannuuthus.com" http://host.docker.internal:3000 >/dev/null 2>&1; then
    echo "   ✅ gateway 可以访问前端服务"
else
    echo "   ❌ gateway 无法访问前端服务"
    echo "   请检查 Vite 配置中的 allowedHosts"
fi

echo ""
echo "✅ 诊断完成"
