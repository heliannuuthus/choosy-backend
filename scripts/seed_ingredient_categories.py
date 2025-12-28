#!/usr/bin/env python3
"""
食材分类初始化脚本
运行: python scripts/seed_ingredient_categories.py [db_path]
"""

import sqlite3
import sys
from datetime import datetime

# 食材分类数据
CATEGORIES = [
    {"key": "meat", "label": "肉禽类"},
    {"key": "seafood", "label": "水产海鲜"},
    {"key": "vegetable", "label": "蔬菜"},
    {"key": "mushroom", "label": "菌菇"},
    {"key": "tofu", "label": "豆制品"},
    {"key": "egg_dairy", "label": "蛋奶"},
    {"key": "staple", "label": "主食"},
    {"key": "dry_goods", "label": "干货"},
    {"key": "seasoning", "label": "调味料"},
    {"key": "sauce", "label": "酱料"},
    {"key": "spice", "label": "香辛料"},
    {"key": "oil", "label": "油脂"},
    {"key": "fruit", "label": "水果"},
    {"key": "nut", "label": "坚果"},
    {"key": "other", "label": "其他"},
]


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else "db/choosy.db"

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print(f"正在初始化食材分类数据: {db_path}")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    inserted = 0
    skipped = 0

    for cat in CATEGORIES:
        # 检查是否已存在
        cursor.execute("SELECT _id FROM ingredient_categories WHERE key = ?", (cat["key"],))
        exists = cursor.fetchone()

        if exists:
            skipped += 1
        else:
            cursor.execute(
                """
                INSERT INTO ingredient_categories (key, label, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (cat["key"], cat["label"], now, now),
            )
            inserted += 1
            print(f"  + {cat['label']} ({cat['key']})")

    conn.commit()
    conn.close()

    print(f"\n✓ 完成: 新增 {inserted} 条, 跳过 {skipped} 条（已存在）")


if __name__ == "__main__":
    main()

