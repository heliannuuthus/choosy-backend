#!/usr/bin/env python3
"""
数据库迁移脚本
运行: python scripts/migrate.py [db_path]
"""

import sqlite3
import sys
import os
from pathlib import Path
from datetime import datetime

# 需要添加时间字段的表
TABLES_TO_ADD_TIMESTAMPS = [
    "recipes",
    "ingredients",
    "steps",
    "additional_notes",
    "tags",
]

# 需要创建的索引
INDEXES = [
    {"name": "idx_ingredients_category", "table": "ingredients", "column": "category"},
]


def column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """检查列是否存在"""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?",
        (table, column),
    )
    return cursor.fetchone()[0] > 0


def add_timestamp_columns(conn: sqlite3.Connection):
    """添加时间字段到现有表"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor = conn.cursor()

    for table in TABLES_TO_ADD_TIMESTAMPS:
        # 添加 created_at
        if not column_exists(conn, table, "created_at"):
            try:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN created_at DATETIME NOT NULL DEFAULT '{now}'"
                )
                print(f"  + {table}.created_at")
            except sqlite3.Error as e:
                print(f"警告: {table} 添加 created_at 失败: {e}")

        # 添加 updated_at
        if not column_exists(conn, table, "updated_at"):
            try:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN updated_at DATETIME NOT NULL DEFAULT '{now}'"
                )
                print(f"  + {table}.updated_at")
            except sqlite3.Error as e:
                print(f"警告: {table} 添加 updated_at 失败: {e}")

    # ingredients 表还需要添加 category 字段
    if not column_exists(conn, "ingredients", "category"):
        try:
            cursor.execute("ALTER TABLE ingredients ADD COLUMN category VARCHAR(32)")
            print("  + ingredients.category")
        except sqlite3.Error as e:
            print(f"警告: ingredients 添加 category 失败: {e}")

    conn.commit()


def create_ingredient_categories_table(conn: sqlite3.Connection):
    """创建 ingredient_categories 表"""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ingredient_categories (
            _id         INTEGER PRIMARY KEY AUTOINCREMENT,
            key         VARCHAR(32) NOT NULL UNIQUE,
            label       VARCHAR(32) NOT NULL,
            created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ingredient_categories_key ON ingredient_categories(key)"
    )
    conn.commit()
    print("  ✓ ingredient_categories")


def create_indexes(conn: sqlite3.Connection):
    """创建索引"""
    cursor = conn.cursor()

    for idx in INDEXES:
        try:
            cursor.execute(
                f"CREATE INDEX IF NOT EXISTS {idx['name']} ON {idx['table']}({idx['column']})"
            )
            print(f"  ✓ {idx['name']}")
        except sqlite3.Error as e:
            print(f"警告: 创建索引 {idx['name']} 失败: {e}")

    conn.commit()


def main():
    # 数据库路径
    db_path = sys.argv[1] if len(sys.argv) > 1 else "db/choosy.db"

    # 确保目录存在
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"正在迁移数据库: {db_path}\n")

    conn = sqlite3.connect(db_path)

    try:
        # Step 1: 添加时间字段到现有表
        print("[1/3] 添加新字段到现有表...")
        add_timestamp_columns(conn)
        print()

        # Step 2: 创建新表
        print("[2/3] 创建新表...")
        create_ingredient_categories_table(conn)
        print()

        # Step 3: 创建索引
        print("[3/3] 创建索引...")
        create_indexes(conn)
        print()

        print("✓ 迁移完成")

        # 打印表信息
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        print(f"当前表: {tables}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()

