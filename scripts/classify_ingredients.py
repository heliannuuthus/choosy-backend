#!/usr/bin/env python3
"""
食材分类脚本
使用 qwen-max 为食材自动分类
"""

import sqlite3
import os
import time
import json
import re
from pathlib import Path
from dotenv import load_dotenv

from langchain_openai import ChatOpenAI

# 加载 .env 文件
load_dotenv(Path(__file__).parent / ".env")

# 配置
DB_PATH = Path(__file__).parent.parent / "db" / "choosy.db"
DASHSCOPE_API_KEY = os.environ.get("DASHSCOPE_API_KEY", "")
MODEL = "qwen-max"
BATCH_SIZE = 50
DELAY_BETWEEN_BATCHES = 0.5


def get_categories(conn: sqlite3.Connection) -> dict:
    """获取所有分类"""
    cursor = conn.cursor()
    cursor.execute("SELECT key, label FROM ingredient_categories")
    return {row[0]: row[1] for row in cursor.fetchall()}


def get_uncategorized_ingredients(conn: sqlite3.Connection) -> list:
    """获取未分类的食材（去重）"""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DISTINCT name FROM ingredients 
        WHERE category IS NULL OR category = ''
    """)
    return [row[0] for row in cursor.fetchall()]


def update_ingredient_category(conn: sqlite3.Connection, name: str, category: str):
    """更新食材分类"""
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE ingredients 
        SET category = ?, updated_at = datetime('now')
        WHERE name = ? AND (category IS NULL OR category = '')
    """, (category, name))
    return cursor.rowcount


def build_prompt(categories: dict) -> str:
    """构建提示模板"""
    cat_desc = "\n".join([f"- {k}: {v}" for k, v in categories.items()])
    
    return f"""你是食材分类专家。请将食材分类到以下类别中：

{cat_desc}

规则：
1. 每个食材只能属于一个分类
2. 只返回 JSON 数组，格式: [{{"name": "食材名", "category": "分类key"}}]
3. 如果无法确定，使用 "other"

请分类以下食材："""


def parse_response(text: str) -> list:
    """解析 AI 响应"""
    text = text.strip()
    
    # 处理 markdown 代码块
    if "```" in text:
        match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
        if match:
            text = match.group(1)
    
    try:
        return json.loads(text)
    except:
        return []


def create_llm():
    """创建 LLM 客户端"""
    return ChatOpenAI(
        model=MODEL,
        api_key=DASHSCOPE_API_KEY,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        temperature=0.1,
        max_tokens=2048,
    )


def main():
    print("=" * 60)
    print("食材分类脚本")
    print("=" * 60)
    
    if not DASHSCOPE_API_KEY:
        print("❌ 请设置环境变量 DASHSCOPE_API_KEY")
        print("   或在 scripts/.env 文件中配置")
        return
    
    if not DB_PATH.exists():
        print(f"❌ 数据库不存在: {DB_PATH}")
        return
    
    print(f"📁 数据库: {DB_PATH}")
    print(f"🤖 模型: {MODEL}")
    print()
    
    conn = sqlite3.connect(DB_PATH)
    
    # 获取分类
    categories = get_categories(conn)
    if not categories:
        print("❌ 请先运行迁移脚本初始化分类数据")
        conn.close()
        return
    
    print(f"📂 可用分类: {list(categories.keys())}")
    print()
    
    # 获取未分类食材
    ingredients = get_uncategorized_ingredients(conn)
    total = len(ingredients)
    
    if total == 0:
        print("✅ 所有食材都已分类")
        conn.close()
        return
    
    print(f"📋 待分类: {total} 种食材")
    print()
    
    # 构建提示和 LLM
    prompt_template = build_prompt(categories)
    llm = create_llm()
    
    updated = 0
    
    # 批量处理
    for i in range(0, total, BATCH_SIZE):
        batch = ingredients[i:i+BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        total_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE
        
        print(f"[{batch_num}/{total_batches}] 处理第 {i+1}-{min(i+BATCH_SIZE, total)} 个...", flush=True)
        
        try:
            # 调用 AI
            full_prompt = prompt_template + "、".join(batch)
            response = llm.invoke(full_prompt)
            results = parse_response(response.content)
            
            # 更新数据库
            for item in results:
                name = item.get("name", "")
                category = item.get("category", "")
                
                if not name or category not in categories:
                    continue
                
                count = update_ingredient_category(conn, name, category)
                if count > 0:
                    updated += count
                    print(f"  ✓ {name} → {categories[category]}")
            
            conn.commit()
            
        except Exception as e:
            print(f"  ❌ 失败: {e}")
        
        if i + BATCH_SIZE < total:
            time.sleep(DELAY_BETWEEN_BATCHES)
    
    conn.close()
    
    print()
    print("=" * 60)
    print(f"✅ 完成! 更新了 {updated} 条记录")
    print("=" * 60)


if __name__ == "__main__":
    main()

