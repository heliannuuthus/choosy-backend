# 网络架构说明

## Gateway 网络配置

### 当前配置

Gateway 容器使用 `host.docker.internal:host-gateway` 来访问宿主机（WSL2）上的服务：

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

### 工作原理

1. **`host.docker.internal`**：Docker/nerdctl 提供的特殊主机名，用于从容器访问宿主机
2. **`host-gateway`**：自动解析为宿主机的网关 IP（在 WSL2 中通常是 WSL2 的网关）
3. **Nginx upstream 配置**：
   - `host.docker.internal:18000` → 访问宿主机上的 Helios 后端服务
   - `host.docker.internal:3000` → 访问宿主机上的 Atlas 前端服务

### 网络流向

```
浏览器 (Windows/WSL)
    ↓ HTTPS:443
https-proxy (容器，监听主机 443)
    ↓ HTTP:80 (Docker 网络)
gateway (容器，内部端口 80)
    ↓ HTTP (通过 host.docker.internal)
宿主机服务 (WSL2)
    - Helios 后端 :18000
    - Atlas 前端 :3000
```

### 验证配置

在 gateway 容器内测试：

```bash
# 检查 host.docker.internal 解析
nerdctl exec helios-gateway cat /etc/hosts | grep host.docker

# 测试连接宿主机服务
nerdctl exec helios-gateway wget -O- http://host.docker.internal:18000/health
nerdctl exec helios-gateway wget -O- http://host.docker.internal:3000
```

### 注意事项

1. **服务必须在宿主机上运行**：Helios 后端和 Atlas 前端需要在 WSL2 内运行并监听对应端口
2. **防火墙**：确保 WSL2 防火墙允许容器访问这些端口
3. **host.docker.internal 支持**：在 nerdctl 中，`host-gateway` 会自动解析为正确的网关 IP

### 如果无法访问宿主机服务

1. **检查服务是否运行**：
   ```bash
   # 在 WSL2 内检查
   netstat -tlnp | grep -E ":(18000|3000)"
   ```

2. **检查 host.docker.internal 解析**：
   ```bash
   nerdctl exec helios-gateway ping host.docker.internal
   ```

3. **使用宿主机 IP**（备选方案）：
   如果 `host.docker.internal` 不工作，可以：
   - 获取 WSL2 IP：`hostname -I | awk '{print $1}'`
   - 在 nginx.conf 中使用具体 IP（不推荐，IP 可能变化）

4. **使用 host 网络模式**（不推荐）：
   ```yaml
   network_mode: "host"
   ```
   这会让容器直接使用宿主机网络，但会失去容器网络隔离。

### WSL2 特殊说明

在 WSL2 中：
- `host.docker.internal` 指向 WSL2 的网关（通常是 `10.255.255.254`）
- 可以访问 WSL2 内运行的服务
- 也可以访问 Windows 宿主机（通过特殊 IP）

当前配置应该可以正常工作，因为：
- Gateway 通过 `host.docker.internal` 访问宿主机
- 服务运行在 WSL2 内，可以通过网关访问
