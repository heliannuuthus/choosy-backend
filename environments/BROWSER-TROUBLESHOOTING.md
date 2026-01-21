# 浏览器访问问题排查

## 问题：curl 可以访问，但浏览器不行

### 可能的原因

1. **证书未安装到浏览器信任存储**
   - mkcert 的 CA 证书需要安装到浏览器的信任存储
   - Windows Chrome 使用 Windows 证书存储
   - WSL 内 Chrome 使用 Linux 证书存储

2. **浏览器缓存**
   - 浏览器可能缓存了之前的错误（SSL 错误、HSTS 等）
   - 需要清除缓存或使用隐私模式

3. **DNS 解析问题**
   - 浏览器可能使用不同的 DNS
   - Windows 浏览器使用 Windows hosts 文件
   - WSL 浏览器使用 WSL hosts 文件

4. **HSTS（HTTP Strict Transport Security）**
   - 浏览器可能缓存了 HSTS 策略
   - 需要清除 HSTS 缓存

## 解决方案

### 1. 确认证书已安装

```bash
# 检查 mkcert CA 位置
mkcert -CAROOT

# 查看 CA 证书
ls -la "$(mkcert -CAROOT)/"
```

### 2. Windows Chrome（如果从 Windows 访问）

Windows Chrome 需要安装 Windows 版本的 mkcert CA：

```powershell
# 在 Windows PowerShell 中运行
# 安装 mkcert（如果未安装）
# choco install mkcert

# 安装 CA 到 Windows 证书存储
mkcert -install
```

### 3. WSL 内 Chrome

如果使用 WSL 内的 Chrome：

```bash
# 确认 mkcert CA 已安装
mkcert -install

# 检查证书位置
ls -la "$(mkcert -CAROOT)/rootCA.pem"
```

### 4. 清除浏览器缓存

**Chrome/Edge：**
1. 打开开发者工具（F12）
2. 右键点击刷新按钮
3. 选择"清空缓存并硬性重新加载"

**或者：**
1. 设置 → 隐私和安全 → 清除浏览数据
2. 选择"缓存的图片和文件"
3. 清除数据

### 5. 清除 HSTS 缓存

**Chrome：**
1. 访问 `chrome://net-internals/#hsts`
2. 在 "Delete domain security policies" 中输入 `atlas.heliannuuthus.com`
3. 点击 "Delete"
4. 对所有域名重复此操作

### 6. 检查证书详情

```bash
# 查看证书信息
openssl x509 -in environments/certs/fullchain.pem -text -noout | grep -E "(Subject:|Issuer:|DNS:)"

# 测试证书
openssl s_client -connect atlas.heliannuuthus.com:443 -servername atlas.heliannuuthus.com < /dev/null
```

### 7. 验证 DNS 解析

```bash
# 在 WSL 内
host atlas.heliannuuthus.com

# 在 Windows PowerShell
nslookup atlas.heliannuuthus.com
```

### 8. 浏览器控制台检查

打开浏览器开发者工具（F12），查看：
- **Console**：是否有 JavaScript 错误
- **Network**：请求是否被阻止，状态码是什么
- **Security**：证书错误详情

## 快速诊断命令

```bash
# 1. 测试 HTTPS 连接
curl -v https://atlas.heliannuuthus.com

# 2. 测试证书
openssl s_client -connect atlas.heliannuuthus.com:443 -servername atlas.heliannuuthus.com

# 3. 检查服务状态
nerdctl compose ps

# 4. 查看 nginx 日志
nerdctl logs helios-https-proxy --tail 50
nerdctl logs helios-gateway --tail 50
```

## 常见错误

### ERR_CERT_AUTHORITY_INVALID
- **原因**：浏览器不信任 mkcert CA
- **解决**：运行 `mkcert -install`（在相应的系统上）

### ERR_CONNECTION_REFUSED
- **原因**：服务未启动或端口未监听
- **解决**：检查 `nerdctl compose ps` 和端口监听

### ERR_SSL_PROTOCOL_ERROR
- **原因**：证书配置错误或 nginx 配置问题
- **解决**：检查 `nerdctl exec helios-https-proxy nginx -t`

### 301/302 重定向循环
- **原因**：HTTP 到 HTTPS 重定向配置问题
- **解决**：检查 nginx 配置中的重定向规则
