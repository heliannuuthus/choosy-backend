#!/usr/bin/env python3
"""
初始化用户偏好选项（忌口、过敏）
运行: python scripts/seed_preference_options.py [db_path]
"""

import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "db" / "choosy.db"

# 忌口选项
TABOO_OPTIONS = [
    ("no_pork", "不吃猪肉"),
    ("no_beef", "不吃牛肉"),
    ("no_lamb", "不吃羊肉"),
    ("no_organ", "不吃内脏"),
    ("no_seafood", "不吃海鲜"),
    ("no_fish", "不吃鱼类"),
    ("no_cilantro", "不吃香菜"),
    ("no_scallion", "不吃葱"),
    ("no_garlic", "不吃蒜"),
    ("no_ginger", "不吃姜"),
    ("no_mushroom", "不吃菌菇"),
    ("no_tofu", "不吃豆制品"),
    ("no_egg", "不吃鸡蛋"),
]

# 过敏选项（基于常见过敏原）
ALLERGY_OPTIONS = [
    ("peanut", "花生过敏"),
    ("tree_nut", "坚果过敏"),
    ("seafood", "海鲜过敏"),
    ("fish", "鱼类过敏"),
    ("shellfish", "贝类过敏"),
    ("milk", "牛奶过敏"),
    ("egg", "鸡蛋过敏"),
    ("soy", "大豆过敏"),
    ("wheat", "小麦过敏"),
    ("sesame", "芝麻过敏"),
]


def seed_options(db_path: Path):
    """初始化选项数据"""
    if not db_path.exists():
        print(f"❌ 数据库不存在: {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    inserted_taboo = 0
    skipped_taboo = 0
    inserted_allergy = 0
    skipped_allergy = 0
    
    print("正在初始化用户偏好选项...\n")
    
    # 插入忌口选项
    print("[1/2] 插入忌口选项...")
    for value, label in TABOO_OPTIONS:
        try:
            cursor.execute(
                "INSERT INTO t_tag (value, label, type) VALUES (?, ?, 'taboo')",
                (value, label)
            )
            print(f"  + {label} ({value})")
            inserted_taboo += 1
        except sqlite3.IntegrityError:
            print(f"  - {label} ({value}) - 已存在，跳过")
            skipped_taboo += 1
    
    conn.commit()
    print(f"  完成: 新增 {inserted_taboo} 条, 跳过 {skipped_taboo} 条\n")
    
    # 插入过敏选项
    print("[2/2] 插入过敏选项...")
    for value, label in ALLERGY_OPTIONS:
        try:
            cursor.execute(
                "INSERT INTO t_tag (value, label, type) VALUES (?, ?, 'allergy')",
                (value, label)
            )
            print(f"  + {label} ({value})")
            inserted_allergy += 1
        except sqlite3.IntegrityError:
            print(f"  - {label} ({value}) - 已存在，跳过")
            skipped_allergy += 1
    
    conn.commit()
    print(f"  完成: 新增 {inserted_allergy} 条, 跳过 {skipped_allergy} 条\n")
    
    conn.close()
    
    print("=" * 60)
    print(f"✓ 初始化完成!")
    print(f"  忌口选项: 新增 {inserted_taboo} 条, 跳过 {skipped_taboo} 条")
    print(f"  过敏选项: 新增 {inserted_allergy} 条, 跳过 {skipped_allergy} 条")
    print("=" * 60)


def main():
    db_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DB_PATH
    
    seed_options(db_path)


if __name__ == "__main__":
    main()
