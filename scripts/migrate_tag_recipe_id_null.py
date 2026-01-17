#!/usr/bin/env python3
"""
迁移脚本：修改 t_tag 表，允许 recipe_id 为 NULL（用于选项）
运行: python scripts/migrate_tag_recipe_id_null.py [db_path]
"""

import sqlite3
import sys
from pathlib import Path


def migrate_tag_table(conn: sqlite3.Connection):
    """修改 t_tag 表，允许 recipe_id 为 NULL"""
    cursor = conn.cursor()
    
    # SQLite 不支持直接修改列的 NOT NULL 约束，需要重建表
    print("[1/4] 检查当前表结构...")
    cursor.execute("PRAGMA table_info(t_tag)")
    columns = cursor.fetchall()
    recipe_id_not_null = any(col[1] == 'recipe_id' and col[3] == 1 for col in columns)
    
    if not recipe_id_not_null:
        print("  ✓ recipe_id 已可为 NULL，跳过迁移")
        return
    
    print("[2/4] 备份现有数据...")
    cursor.execute("SELECT * FROM t_tag")
    existing_data = cursor.fetchall()
    print(f"  ✓ 备份了 {len(existing_data)} 条记录")
    
    print("[3/4] 重建表结构...")
    # 创建新表（允许 recipe_id 为 NULL）
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS t_tag_new (
            _id         INTEGER PRIMARY KEY AUTOINCREMENT,
            recipe_id   VARCHAR(16),
            value       VARCHAR(50) NOT NULL,
            label       VARCHAR(50) NOT NULL,
            type        VARCHAR(20) NOT NULL,
            created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 复制数据
    cursor.executemany(
        "INSERT INTO t_tag_new (_id, recipe_id, value, label, type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        existing_data
    )
    
    # 删除旧表
    cursor.execute("DROP TABLE t_tag")
    
    # 重命名新表
    cursor.execute("ALTER TABLE t_tag_new RENAME TO t_tag")
    
    print("[4/4] 重建索引...")
    # 重建索引
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_t_tag_recipe_id ON t_tag(recipe_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_t_tag_value ON t_tag(value)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_t_tag_type ON t_tag(type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_t_tag_type_recipe_id ON t_tag(type, recipe_id)")
    
    conn.commit()
    print("  ✓ 迁移完成")


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else "db/choosy.db"
    db_file = Path(db_path)
    
    if not db_file.exists():
        print(f"❌ 数据库不存在: {db_path}")
        return
    
    print(f"正在迁移数据库: {db_path}\n")
    
    conn = sqlite3.connect(db_path)
    
    try:
        migrate_tag_table(conn)
        print("\n✓ 迁移完成")
    except Exception as e:
        print(f"\n❌ 迁移失败: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
