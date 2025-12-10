#!/usr/bin/env python3
"""
从 blacksmith 数据集导入精炼后的菜谱数据到 SQLite 数据库
"""
import json
import os
import re
import sys
import hashlib
from pathlib import Path
from typing import Optional, Tuple

# 添加项目根目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.orm import Session
from app.core.database import engine, SessionLocal, Base
from app.models.recipe import Recipe, Ingredient, Step, AdditionalNote


# ============= 工具函数 =============

def parse_time_minutes(time_str: Optional[str]) -> Optional[int]:
    """
    解析时间字符串为分钟数
    
    Examples:
        "5分钟" -> 5
        "30分钟" -> 30
        "1小时" -> 60
        "1-4分钟" -> 4 (取最大值)
        "3-4分钟" -> 4
    """
    if not time_str:
        return None
    
    # 移除空格
    time_str = time_str.strip()
    
    total_minutes = 0
    
    # 匹配小时
    hour_match = re.search(r'(\d+)\s*小时', time_str)
    if hour_match:
        total_minutes += int(hour_match.group(1)) * 60
    
    # 匹配分钟 (支持范围如 "3-4分钟")
    minute_match = re.search(r'(\d+)(?:-(\d+))?\s*分钟?', time_str)
    if minute_match:
        if minute_match.group(2):
            # 如果是范围，取最大值
            total_minutes += int(minute_match.group(2))
        else:
            total_minutes += int(minute_match.group(1))
    
    return total_minutes if total_minutes > 0 else None


def parse_servings(servings_str: Optional[str]) -> int:
    """
    解析份量字符串为整数
    
    Examples:
        "1人份" -> 1
        "2-3人份" -> 2 (取最小值)
        "4人份" -> 4
    """
    if not servings_str:
        return 1
    
    # 匹配数字 (支持范围如 "2-3人份")
    match = re.search(r'(\d+)(?:-(\d+))?', servings_str)
    if match:
        # 如果是范围，取最小值
        return int(match.group(1))
    
    return 1


def parse_quantity_and_unit(amount_str: Optional[str]) -> Tuple[Optional[float], Optional[str]]:
    """
    解析数量字符串为数量和单位
    
    Examples:
        "10克" -> (10.0, "克")
        "500ml" -> (500.0, "ml")
        "2片" -> (2.0, "片")
        "10-12只" -> (10.0, "只")
        "1个" -> (1.0, "个")
        "适量" -> (None, None)
    """
    if not amount_str:
        return None, None
    
    amount_str = amount_str.strip()
    
    # 如果是模糊用量，返回 None
    vague_patterns = ['适量', '少许', '若干', '一些']
    for pattern in vague_patterns:
        if pattern in amount_str:
            return None, None
    
    # 匹配数字和单位 (支持范围如 "10-12只")
    match = re.match(r'(\d+(?:\.\d+)?)(?:-\d+(?:\.\d+)?)?\s*(.+)?', amount_str)
    if match:
        quantity = float(match.group(1))
        unit = match.group(2).strip() if match.group(2) else None
        return quantity, unit
    
    return None, None


def generate_recipe_id(category: str, name: str) -> str:
    """
    生成菜谱唯一 ID
    
    使用 category 和 name 的组合进行 hash 生成短 ID
    """
    key = f"{category}_{name}"
    hash_value = hashlib.md5(key.encode('utf-8')).hexdigest()[:12]
    return f"{category}_{hash_value}"


def get_category_name(category: str) -> str:
    """
    获取分类的中文名称
    """
    category_map = {
        'aquatic': '水产',
        'breakfast': '早餐',
        'condiment': '调味品',
        'drink': '饮品',
        'meat_dish': '肉类',
        'semi-finished': '半成品',
        'soup': '汤类',
        'staple': '主食',
        'vegetable_dish': '素菜',
    }
    return category_map.get(category, category)


# ============= 导入逻辑 =============

def import_recipe(db: Session, json_path: Path, category: str) -> Optional[str]:
    """
    从 JSON 文件导入单个菜谱
    
    Args:
        db: 数据库会话
        json_path: JSON 文件路径
        category: 菜谱分类
        
    Returns:
        导入成功的菜谱 ID，失败返回 None
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  ✗ 无法读取文件 {json_path}: {e}")
        return None
    
    # 检查是否有 refined 数据
    refined = data.get('refined')
    if not refined:
        print(f"  ✗ 文件 {json_path.name} 没有 refined 数据，跳过")
        return None
    
    # 基础信息
    name = data.get('name', refined.get('title', ''))
    if not name:
        print(f"  ✗ 文件 {json_path.name} 没有名称，跳过")
        return None
    
    recipe_id = generate_recipe_id(category, name)
    
    # 检查是否已存在
    existing = db.query(Recipe).filter(Recipe.id == recipe_id).first()
    if existing:
        print(f"  ○ 菜谱 '{name}' 已存在，跳过")
        return None
    
    # 解析时间和份量
    prep_time = parse_time_minutes(refined.get('prep_time'))
    cook_time = parse_time_minutes(refined.get('cook_time'))
    total_time = None
    if prep_time is not None or cook_time is not None:
        total_time = (prep_time or 0) + (cook_time or 0)
    
    servings = parse_servings(refined.get('servings'))
    
    # 创建菜谱主记录
    recipe = Recipe(
        id=recipe_id,
        name=name,
        description=refined.get('description'),
        source_path=data.get('path'),
        image_path=None,
        images=[],
        category=category,
        difficulty=refined.get('difficulty', 1),
        tags=[],
        servings=servings,
        prep_time_minutes=prep_time,
        cook_time_minutes=cook_time,
        total_time_minutes=total_time,
    )
    
    # 添加食材
    for ing in refined.get('ingredients', []):
        quantity, unit = parse_quantity_and_unit(ing.get('amount'))
        ingredient = Ingredient(
            recipe_id=recipe_id,
            name=ing.get('name', ''),
            quantity=quantity,
            unit=unit,
            text_quantity=ing.get('amount', ''),
            notes=ing.get('note'),
        )
        recipe.ingredients.append(ingredient)
    
    # 添加步骤
    for step_data in refined.get('steps', []):
        # 组合 action 和 tips
        description = step_data.get('action', '')
        if step_data.get('tips'):
            description += f"\n\n💡 提示：{step_data.get('tips')}"
        
        step = Step(
            recipe_id=recipe_id,
            step=step_data.get('order', 0),
            description=description,
        )
        recipe.steps.append(step)
    
    # 添加小贴士
    for tip in refined.get('tips', []):
        note = AdditionalNote(
            recipe_id=recipe_id,
            note=tip,
        )
        recipe.additional_notes.append(note)
    
    db.add(recipe)
    return recipe_id


def import_all_recipes(dataset_path: Path, db_url: str = None):
    """
    导入所有菜谱数据
    
    Args:
        dataset_path: 数据集根目录路径
        db_url: 可选的数据库 URL
    """
    dishes_path = dataset_path / 'dishes'
    
    if not dishes_path.exists():
        print(f"错误: 找不到 dishes 目录: {dishes_path}")
        return
    
    # 确保数据库表存在
    Base.metadata.create_all(bind=engine)
    
    # 统计
    total_imported = 0
    total_skipped = 0
    total_failed = 0
    
    # 获取数据库会话
    db = SessionLocal()
    
    try:
        # 遍历所有分类目录
        categories = sorted([d for d in dishes_path.iterdir() if d.is_dir()])
        
        for category_path in categories:
            category = category_path.name
            category_display = get_category_name(category)
            
            json_files = list(category_path.glob('*.json'))
            print(f"\n📂 {category_display} ({category}) - 共 {len(json_files)} 个菜谱")
            
            category_imported = 0
            
            for json_path in sorted(json_files):
                result = import_recipe(db, json_path, category)
                if result:
                    print(f"  ✓ 导入成功: {json_path.stem}")
                    category_imported += 1
                    total_imported += 1
                else:
                    if '已存在' in str(result) if result else False:
                        total_skipped += 1
                    else:
                        total_failed += 1
            
            # 每个分类提交一次
            db.commit()
            print(f"  → 本分类导入: {category_imported} 个")
        
        print(f"\n" + "=" * 50)
        print(f"✅ 导入完成!")
        print(f"  - 成功导入: {total_imported} 个")
        print(f"  - 跳过 (已存在/无数据): {total_skipped + total_failed} 个")
        
    except Exception as e:
        db.rollback()
        print(f"\n❌ 导入失败: {e}")
        raise
    finally:
        db.close()


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='导入 HowToCook 菜谱数据到 SQLite')
    parser.add_argument(
        '--dataset',
        type=str,
        default='/home/heliannuuthus/Code/blacksmith/datasets/howtocook',
        help='数据集根目录路径 (默认: ../blacksmith/datasets/howtocook)'
    )
    parser.add_argument(
        '--clear',
        action='store_true',
        help='导入前清空现有数据'
    )
    
    args = parser.parse_args()
    
    dataset_path = Path(args.dataset)
    
    if not dataset_path.exists():
        print(f"错误: 找不到数据集目录: {dataset_path}")
        sys.exit(1)
    
    print(f"🍳 HowToCook 菜谱数据导入工具")
    print(f"=" * 50)
    print(f"数据集路径: {dataset_path}")
    
    if args.clear:
        print("\n⚠️  正在清空现有数据...")
        db = SessionLocal()
        try:
            db.query(AdditionalNote).delete()
            db.query(Step).delete()
            db.query(Ingredient).delete()
            db.query(Recipe).delete()
            db.commit()
            print("✓ 已清空所有菜谱数据")
        finally:
            db.close()
    
    import_all_recipes(dataset_path)


if __name__ == '__main__':
    main()

