# SSL 证书目录

本地开发环境的 SSL 证书文件应放在此目录下。

## 生成证书

使用 `mkcert` 生成本地信任的证书：

```bash
cd environments/certs

# 安装 mkcert（如果未安装）
# macOS: brew install mkcert
# Linux: 参考 https://github.com/FiloSottile/mkcert

# 安装本地 CA
mkcert -install

# 生成 RSA 证书（默认）
mkcert auth.heliannuuthus.com hermes.heliannuuthus.com zwei.heliannuuthus.com atlas.heliannuuthus.com

# 或者生成 ECC 证书（推荐，更小更快）
mkcert -ecdsa auth.heliannuuthus.com hermes.heliannuuthus.com zwei.heliannuuthus.com atlas.heliannuuthus.com

# 重命名文件以匹配 nginx 配置
mv auth.heliannuuthus.com+3.pem fullchain.pem
mv auth.heliannuuthus.com+3-key.pem privkey.pem
```

### 证书类型选择

- **RSA（默认）**：兼容性最好，证书文件较大
- **ECC（-ecdsa）**：推荐使用，证书文件更小，性能更好，安全性更高
  - mkcert 使用默认椭圆曲线（通常是 secp256r1/P-256）
  - 不支持指定特定曲线，如需自定义曲线请使用 OpenSSL

## 文件说明

- `fullchain.pem` - 完整证书链（证书 + 中间证书）
- `privkey.pem` - 私钥文件

## 注意事项

- 证书文件已添加到 `.gitignore`，不会被提交到仓库
- 每个开发者需要在自己的环境中生成证书
- 生产环境不使用此目录，SSL 终止在 Cloudflare
