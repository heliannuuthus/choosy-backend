#!/usr/bin/env python3
"""
菜谱标签生成脚本
使用 LangChain + 阿里云百炼 qwen-max 模型为菜谱生成标签
直接插入 tags 表（无需关联表）
"""

import sqlite3
import os
import time
import json
import re
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# 配置
DB_PATH = Path(__file__).parent.parent / "db" / "choosy.db"
DASHSCOPE_API_KEY = os.environ.get("DASHSCOPE_API_KEY", "")
MODEL = "qwen-max"
BATCH_SIZE = 5
DELAY_BETWEEN_BATCHES = 1

# 预定义标签（硬编码）
TAGS = {
    "cuisine": [
        ("sichuan", "川菜"), ("cantonese", "粤菜"), ("hunan", "湘菜"),
        ("shandong", "鲁菜"), ("jiangsu", "苏菜"), ("zhejiang", "浙菜"),
        ("fujian", "闽菜"), ("anhui", "徽菜"), ("dongbei", "东北菜"),
        ("northwest", "西北菜"), ("yunnan", "云贵菜"), ("beijing", "京菜"),
        ("shanghai", "本帮菜"), ("hakka", "客家菜"), ("chaozhou", "潮州菜"),
        ("french", "法餐"), ("italian", "意餐"), ("american", "美式"),
        ("spanish", "西班牙菜"), ("mexican", "墨西哥菜"), ("german", "德餐"),
        ("british", "英式"), ("japanese", "日料"), ("korean", "韩餐"),
        ("thai", "泰餐"), ("vietnamese", "越南菜"), ("indian", "印度菜"),
        ("southeast_asian", "东南亚"), ("middle_eastern", "中东菜"),
    ],
    "flavor": [
        ("spicy_numbing", "麻辣"), ("spicy", "香辣"), ("mild_spicy", "微辣"),
        ("sweet_sour", "酸甜"), ("savory", "咸鲜"), ("light", "清淡"),
        ("sweet", "甜"), ("sour", "酸"), ("bitter", "苦"), ("umami", "鲜"),
        ("garlic", "蒜香"), ("scallion", "葱香"), ("ginger", "姜香"),
        ("smoky", "烟熏"), ("fermented", "酱香"), ("cumin", "孜然"),
        ("curry", "咖喱"), ("sesame", "芝麻香"), ("vinegar", "醋香"), ("wine", "酒香"),
    ],
    "scene": [
        ("summer_cool", "夏日清凉"), ("winter_warm", "冬日暖身"),
        ("rainy_comfort", "雨天治愈"), ("autumn_nourish", "秋季滋补"),
        ("spring_fresh", "春季尝鲜"), ("quick_meal", "快手菜"),
        ("party", "聚会宴客"), ("late_night", "夜宵"), ("breakfast", "早餐"),
        ("lunch_box", "便当"), ("picnic", "野餐"), ("healthy", "健康轻食"),
        ("low_fat", "低脂"), ("high_protein", "高蛋白"), ("vegetarian", "素食"),
        ("hangover", "解酒"), ("appetizer", "开胃"), ("comfort_food", "治愈系"),
        ("nourishing", "滋补"), ("kids_friendly", "适合儿童"),
        ("elderly_friendly", "适合老人"), ("beginner", "新手友好"),
        ("one_pot", "一锅出"), ("no_cook", "免开火"), ("microwave", "微波炉"),
        ("air_fryer", "空气炸锅"), ("slow_cook", "慢炖"),
    ],
}

# value -> label 映射
TAG_LABELS = {}
for tag_type, tags in TAGS.items():
    for value, label in tags:
        TAG_LABELS[value] = label


# ==================== Pydantic 结构化输出 ====================

class RecipeTags(BaseModel):
    """菜谱标签结构"""
    cuisine: str = Field(description="菜系，只能选1个")
    flavors: List[str] = Field(description="口味，选1-2个")
    scenes: List[str] = Field(description="场景，选1-3个")


# ==================== 数据库操作 ====================

def get_recipes_without_tags(conn: sqlite3.Connection, limit: int = None):
    cursor = conn.cursor()
    query = """
        SELECT r.recipe_id, r.name, r.description, r.category
        FROM t_recipe r
        WHERE NOT EXISTS (
            SELECT 1 FROM t_recipe_tag rt WHERE rt.recipe_id = r.recipe_id
        )
        ORDER BY r.recipe_id
    """
    if limit:
        query += f" LIMIT {limit}"
    cursor.execute(query)
    return cursor.fetchall()


def get_recipe_ingredients(conn: sqlite3.Connection, recipe_id: str):
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM t_ingredient WHERE recipe_id = ?", (recipe_id,))
    return [row[0] for row in cursor.fetchall()]


def add_tag(conn: sqlite3.Connection, recipe_id: str, value: str, tag_type: str):
    """添加标签：先确保标签定义存在，然后创建关联关系"""
    label = TAG_LABELS.get(value, value)
    cursor = conn.cursor()
    
    # 1. 确保标签定义存在（如果不存在则创建）
    cursor.execute(
        "INSERT OR IGNORE INTO t_tag (value, label, type) VALUES (?, ?, ?)",
        (value, label, tag_type)
    )
    
    # 2. 创建关联关系
    cursor.execute(
        "INSERT OR IGNORE INTO t_recipe_tag (recipe_id, tag_value, tag_type) VALUES (?, ?, ?)",
        (recipe_id, value, tag_type)
    )


# ==================== LangChain 设置 ====================

def format_options(tag_list):
    return ", ".join([f"{v}({l})" for v, l in tag_list])


def build_prompt_template() -> ChatPromptTemplate:
    """构建 LangChain 提示模板"""
    cuisine_options = format_options(TAGS["cuisine"])
    flavor_options = format_options(TAGS["flavor"])
    scene_options = format_options(TAGS["scene"])
    
    system_text = f"""你是一个专业的烹饪专家，擅长分析菜谱并为其打标签。

请根据菜谱信息，从以下标签中选择合适的标签：

菜系(cuisine)可选值: {cuisine_options}

口味(flavor)可选值: {flavor_options}

场景(scene)可选值: {scene_options}

要求：
1. cuisine 必选1个
2. flavors 必选1-2个  
3. scenes 必选1-3个
4. 只能使用上面列出的 value 值

直接返回JSON: {{{{"cuisine":"值","flavors":["值"],"scenes":["值"]}}}}"""

    human_template = """菜名：{name}
描述：{description}
分类：{category}
食材：{ingredients}"""

    return ChatPromptTemplate.from_messages([
        ("system", system_text),
        ("human", human_template)
    ])


def parse_json_response(text: str) -> Optional[dict]:
    """从响应文本中提取 JSON"""
    try:
        return json.loads(text.strip())
    except:
        pass
    
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except:
            pass
    
    match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except:
            pass
    
    return None


def create_chain():
    """创建 LangChain 链"""
    llm = ChatOpenAI(
        model=MODEL,
        api_key=DASHSCOPE_API_KEY,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        temperature=0.3,
    )
    prompt = build_prompt_template()
    return prompt | llm | StrOutputParser()


# ==================== 主流程 ====================

def main():
    print("=" * 60)
    print("菜谱标签生成脚本 (LangChain)")
    print("方案: 菜系×1 + 口味×1-2 + 场景×1-3")
    print("=" * 60)
    
    if not DASHSCOPE_API_KEY:
        print("❌ 请设置环境变量 DASHSCOPE_API_KEY")
        return
    
    if not DB_PATH.exists():
        print(f"❌ 数据库不存在: {DB_PATH}")
        return
    
    print(f"📁 数据库: {DB_PATH}")
    print(f"🤖 模型: {MODEL}")
    print()
    
    conn = sqlite3.connect(DB_PATH)
    
    # 获取待处理菜谱
    recipes = get_recipes_without_tags(conn)
    total = len(recipes)
    
    if total == 0:
        print("✅ 所有菜谱都已有标签")
        conn.close()
        return
    
    print(f"📋 待处理: {total} 个")
    print()
    
    chain = create_chain()
    
    success = 0
    failed = 0
    
    for i, (recipe_id, name, description, category) in enumerate(recipes):
        print(f"[{i+1}/{total}] {name}", end=" ", flush=True)
        
        ingredients = get_recipe_ingredients(conn, recipe_id)
        
        try:
            response = chain.invoke({
                "name": name,
                "description": description or "无",
                "category": category or "无",
                "ingredients": ", ".join(ingredients) if ingredients else "无"
            })
            
            result = parse_json_response(response)
            if not result:
                print(f"❌ 无法解析: {response[:50]}...")
                failed += 1
                continue
            
            tag_count = 0
            output_parts = []
            
            # 菜系
            cuisine = result.get("cuisine", "")
            if cuisine and cuisine in TAG_LABELS:
                add_tag(conn, recipe_id, cuisine, "cuisine")
                tag_count += 1
                output_parts.append(TAG_LABELS[cuisine])
            
            # 口味
            for flavor in result.get("flavors", [])[:2]:
                if flavor in TAG_LABELS:
                    add_tag(conn, recipe_id, flavor, "flavor")
                    tag_count += 1
                    output_parts.append(TAG_LABELS[flavor])
            
            # 场景
            for scene in result.get("scenes", [])[:3]:
                if scene in TAG_LABELS:
                    add_tag(conn, recipe_id, scene, "scene")
                    tag_count += 1
                    output_parts.append(TAG_LABELS[scene])
            
            conn.commit()
            print(f"✅ {'/'.join(output_parts)}")
            success += 1
            
        except Exception as e:
            print(f"❌ {e}")
            failed += 1
        
        if (i + 1) % BATCH_SIZE == 0 and i + 1 < total:
            time.sleep(DELAY_BETWEEN_BATCHES)
    
    conn.close()
    
    print()
    print("=" * 60)
    print(f"✅ 完成! 成功: {success}, 失败: {failed}")
    print("=" * 60)


if __name__ == "__main__":
    main()
