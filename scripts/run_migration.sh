'#!/bin/bash
# 数据库迁移脚本
# 运行: bash scripts/run_migration.sh [db_path]

set -e

DB_PATH="${1:-db/choosy.db}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "Choosy 数据库迁移"
echo "数据库: $DB_PATH"
echo "=========================================="
echo

# Step 1: 表结构迁移
echo "[1/2] 执行表结构迁移..."
python3 scripts/migrate.py "$DB_PATH"
echo

# Step 2: 初始化食材分类
echo "[2/2] 初始化食材分类数据..."
python3 scripts/seed_ingredient_categories.py "$DB_PATH"
echo

echo "=========================================="
echo "✓ 迁移完成"
echo "=========================================="

'