#!/usr/bin/env python3
"""
迁移脚本：将 t_tag 表重构为关联表结构
1. 提取所有唯一的标签定义，插入到新的 t_tag 表（移除 recipe_id）
2. 提取所有 recipe_id 不为 NULL 的记录，插入到 t_recipe_tag 关联表
3. 删除旧表，重命名新表

运行: python scripts/migrate_to_recipe_tag_table.py [db_path]
"""

import sqlite3
import sys
from pathlib import Path


def migrate_to_recipe_tag_table(conn: sqlite3.Connection):
    """迁移到关联表结构"""
    cursor = conn.cursor()
    
    print("[1/5] 检查当前表结构...")
    # 检查是否存在旧表
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='t_tag'")
    if not cursor.fetchone():
        print("  ❌ t_tag 表不存在")
        return False
    
    # 检查是否已经迁移过
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='t_recipe_tag'")
    if cursor.fetchone():
        print("  ✓ 已存在 t_recipe_tag 表，可能已经迁移过")
        response = input("  是否继续迁移？(y/N): ")
        if response.lower() != 'y':
            return False
    
    print("[2/5] 备份现有数据...")
    # 备份旧数据
    cursor.execute("SELECT * FROM t_tag")
    old_tags = cursor.fetchall()
    print(f"  ✓ 备份了 {len(old_tags)} 条记录")
    
    print("[3/5] 创建新表结构...")
    # 创建新的 t_tag 表（不包含 recipe_id）
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS t_tag_new (
            _id         INTEGER PRIMARY KEY AUTOINCREMENT,
            value       VARCHAR(50) NOT NULL,
            label       VARCHAR(50) NOT NULL,
            type        VARCHAR(20) NOT NULL,
            created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 创建关联表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS t_recipe_tag (
            _id         INTEGER PRIMARY KEY AUTOINCREMENT,
            recipe_id   VARCHAR(32) NOT NULL,
            tag_value   VARCHAR(50) NOT NULL,
            tag_type    VARCHAR(20) NOT NULL,
            created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(recipe_id, tag_value, tag_type)
        )
    """)
    
    print("[4/5] 迁移数据...")
    # 1. 提取所有唯一的标签定义（value + type）
    cursor.execute("""
        SELECT DISTINCT value, label, type, MIN(created_at) as created_at, MIN(updated_at) as updated_at
        FROM t_tag
        GROUP BY value, type
    """)
    unique_tags = cursor.fetchall()
    
    tag_inserted = 0
    tag_skipped = 0
    for value, label, tag_type, created_at, updated_at in unique_tags:
        try:
            cursor.execute(
                "INSERT INTO t_tag_new (value, label, type, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (value, label, tag_type, created_at, updated_at)
            )
            tag_inserted += 1
        except sqlite3.IntegrityError:
            tag_skipped += 1
    
    print(f"  ✓ 标签定义: 新增 {tag_inserted} 条, 跳过 {tag_skipped} 条")
    
    # 2. 提取所有 recipe_id 不为 NULL 的记录，插入到关联表
    cursor.execute("""
        SELECT recipe_id, value, type, MIN(created_at) as created_at
        FROM t_tag
        WHERE recipe_id IS NOT NULL
        GROUP BY recipe_id, value, type
    """)
    recipe_tags = cursor.fetchall()
    
    relation_inserted = 0
    relation_skipped = 0
    for recipe_id, tag_value, tag_type, created_at in recipe_tags:
        try:
            cursor.execute(
                "INSERT INTO t_recipe_tag (recipe_id, tag_value, tag_type, created_at) VALUES (?, ?, ?, ?)",
                (recipe_id, tag_value, tag_type, created_at)
            )
            relation_inserted += 1
        except sqlite3.IntegrityError:
            relation_skipped += 1
    
    print(f"  ✓ 关联关系: 新增 {relation_inserted} 条, 跳过 {relation_skipped} 条")
    
    print("[5/5] 重建索引和替换表...")
    # 创建索引
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_t_tag_value ON t_tag_new(value)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_t_tag_type ON t_tag_new(type)")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_t_tag_type_value ON t_tag_new(type, value)")
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_t_recipe_tag_recipe_id ON t_recipe_tag(recipe_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_t_recipe_tag_tag_value ON t_recipe_tag(tag_value)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_t_recipe_tag_tag_type ON t_recipe_tag(tag_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_t_recipe_tag_recipe_type ON t_recipe_tag(recipe_id, tag_type)")
    
    # 删除旧表
    cursor.execute("DROP TABLE t_tag")
    
    # 重命名新表
    cursor.execute("ALTER TABLE t_tag_new RENAME TO t_tag")
    
    conn.commit()
    print("  ✓ 迁移完成")
    
    return True


def main():
    db_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent.parent / "db" / "choosy.db"
    
    if not db_path.exists():
        print(f"❌ 数据库不存在: {db_path}")
        return
    
    print(f"正在迁移数据库: {db_path}\n")
    
    conn = sqlite3.connect(db_path)
    
    try:
        if migrate_to_recipe_tag_table(conn):
            print("\n✓ 迁移成功完成")
        else:
            print("\n⚠ 迁移未完成")
    except Exception as e:
        print(f"\n❌ 迁移失败: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
