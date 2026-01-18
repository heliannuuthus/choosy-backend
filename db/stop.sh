#!/bin/bash
# MySQL 停止脚本（适用于 nerdctl + containerd）

set -e

CONTAINER_NAME="zwei-mysql"
CLEAN_VOLUMES=false

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN_VOLUMES=true
            shift
            ;;
        *)
            echo "未知参数: $1"
            echo "用法: $0 [--clean]"
            echo "  --clean  删除容器时同时清理数据卷"
            exit 1
            ;;
    esac
done

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}正在停止 MySQL 容器...${NC}"
export PATH="$HOME/bin:$PATH"
nerdctl stop $CONTAINER_NAME 2>/dev/null || echo -e "${YELLOW}容器未运行${NC}"

echo -e "${YELLOW}正在删除容器...${NC}"
nerdctl rm $CONTAINER_NAME 2>/dev/null || echo -e "${YELLOW}容器不存在${NC}"

if [ "$CLEAN_VOLUMES" = true ]; then
    echo -e "${YELLOW}正在清理数据卷...${NC}"
    nerdctl volume rm zwei_mysql_data 2>/dev/null && echo -e "${GREEN}已删除 zwei_mysql_data${NC}" || echo -e "${YELLOW}zwei_mysql_data 不存在或仍在使用${NC}"
    nerdctl volume rm zwei_mysql_logs 2>/dev/null && echo -e "${GREEN}已删除 zwei_mysql_logs${NC}" || echo -e "${YELLOW}zwei_mysql_logs 不存在或仍在使用${NC}"
    echo -e "${GREEN}完成！数据卷已清理${NC}"
else
    echo -e "${GREEN}完成！${NC}"
    echo ""
    echo -e "${YELLOW}注意: 数据卷已保留，重新启动时会自动使用现有数据${NC}"
    echo -e "${YELLOW}如需删除数据卷，请使用: $0 --clean${NC}"
fi