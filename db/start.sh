#!/bin/bash
# MySQL 启动脚本（适用于 nerdctl + containerd）

set -e

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 默认配置
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD:-root}
MYSQL_DATABASE=${MYSQL_DATABASE:-zwei}
MYSQL_USER=${MYSQL_USER:-zwei}
MYSQL_PASSWORD=${MYSQL_PASSWORD:-zwei}
CONTAINER_NAME="zwei-mysql"
# 阿里云 ACR 配置（请根据实际情况修改命名空间）
ACR_NAMESPACE=${ACR_NAMESPACE:-heliannuuthus}
ACR_REGISTRY="registry.cn-beijing.aliyuncs.com"
IMAGE_NAME="${ACR_REGISTRY}/${ACR_NAMESPACE}/zwei-db:latest"

echo -e "${GREEN}=== Zwei MySQL 启动脚本 ===${NC}"
echo "容器名称: $CONTAINER_NAME"
echo "镜像名称: $IMAGE_NAME"
echo ""

# 检查是否已存在容器
if nerdctl ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${YELLOW}发现已存在的容器，正在停止并删除...${NC}"
    nerdctl stop $CONTAINER_NAME 2>/dev/null || true
    nerdctl rm $CONTAINER_NAME 2>/dev/null || true
    # 等待容器完全删除，避免 volume 仍被引用
    sleep 1
fi

# 检查镜像是否存在，不存在则从阿里云 ACR 拉取
if nerdctl images --format "{{.Repository}}:{{.Tag}}" | grep -q "^${IMAGE_NAME}$"; then
    echo -e "${GREEN}镜像已存在${NC}"
else
    echo -e "${YELLOW}镜像不存在，正在从阿里云 ACR 拉取...${NC}"
    if ! nerdctl pull $IMAGE_NAME 2>/dev/null; then
        echo -e "${RED}拉取失败，请检查 ACR 登录状态: nerdctl login registry.cn-beijing.aliyuncs.com${NC}"
        exit 1
    fi
fi


# 启动容器
echo -e "${GREEN}启动 MySQL 容器...${NC}"
# 由于我们已经在上面创建了 volume，nerdctl run 挂载时可能会输出警告
# 这是正常的，因为 volume 已经存在。将警告重定向到 /dev/null
nerdctl run -d \
    --name $CONTAINER_NAME \
    -p 3306:3306 \
    -e MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASSWORD" \
    -e MYSQL_DATABASE="$MYSQL_DATABASE" \
    -e MYSQL_USER="$MYSQL_USER" \
    -e MYSQL_PASSWORD="$MYSQL_PASSWORD" \
    --memory=450m \
    --cpus=1.5 \
    -v zwei_mysql_data:/var/lib/mysql \
    -v zwei_mysql_logs:/var/log/mysql \
    $IMAGE_NAME

# 等待几秒查看启动状态
echo -e "${YELLOW}等待容器启动...${NC}"
sleep 5

# 检查容器状态
CONTAINER_STATUS=$(nerdctl ps -a --filter "name=${CONTAINER_NAME}" --format "{{.Status}}" 2>/dev/null || echo "")

if nerdctl ps --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${GREEN}容器运行正常，设置自动重启...${NC}"
    nerdctl update --restart unless-stopped $CONTAINER_NAME
elif [ -n "$CONTAINER_STATUS" ]; then
    echo -e "${RED}容器启动失败！${NC}"
    echo -e "${YELLOW}容器状态：${NC}"
    nerdctl ps -a --filter "name=${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Status}}"
    echo ""
    echo -e "${YELLOW}最后 50 行日志：${NC}"
    nerdctl logs $CONTAINER_NAME 2>&1 | tail -50
    echo ""
    echo -e "${YELLOW}提示：如果数据目录已损坏，可以删除数据卷重新初始化：${NC}"
    echo "  nerdctl volume rm zwei_mysql_data zwei_mysql_logs"
    exit 1
else
    echo -e "${RED}容器创建失败！${NC}"
    exit 1
fi

echo -e "${GREEN}容器已启动！${NC}"
echo ""
echo "查看日志: nerdctl logs -f $CONTAINER_NAME"
echo "查看状态: nerdctl ps | grep $CONTAINER_NAME"
echo "停止容器: nerdctl stop $CONTAINER_NAME"
echo "删除容器: nerdctl rm $CONTAINER_NAME"
