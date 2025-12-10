"""
菜谱 API 路由
"""
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.recipe import (
    CategoryResponse,
    RecipeCreate,
    RecipeUpdate,
    RecipeResponse,
    RecipeListItem,
)
from app.services.recipe import RecipeService

router = APIRouter(tags=["recipes"])

# 分类中文名称映射
CATEGORY_NAMES: Dict[str, str] = {
    "aquatic": "水产",
    "breakfast": "早餐",
    "condiment": "调味品",
    "drink": "饮品",
    "meat_dish": "肉类",
    "semi-finished": "半成品",
    "soup": "汤类",
    "staple": "主食",
    "vegetable_dish": "素菜",
}


@router.post("/", response_model=RecipeResponse, status_code=201)
async def create_recipe(
    recipe: RecipeCreate,
    db: Session = Depends(get_db),
):
    """创建新菜谱"""
    try:
        db_recipe = RecipeService.create_recipe(db, recipe)
        return db_recipe
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/", response_model=List[RecipeListItem])
async def get_recipes(
    category: Optional[str] = Query(None, description="菜谱分类"),
    search: Optional[str] = Query(None, description="搜索关键词"),
    limit: int = Query(100, ge=1, le=500, description="返回数量限制"),
    offset: int = Query(0, ge=0, description="偏移量"),
    db: Session = Depends(get_db),
):
    """获取菜谱列表，支持分类筛选和搜索"""
    recipes = RecipeService.get_recipes(
        db=db,
        category=category,
        search=search,
        limit=limit,
        offset=offset,
    )
    return recipes


@router.get("/{recipe_id}", response_model=RecipeResponse)
async def get_recipe(
    recipe_id: str,
    db: Session = Depends(get_db),
):
    """根据 ID 获取菜谱详情"""
    recipe = RecipeService.get_recipe(db, recipe_id)
    if not recipe:
        raise HTTPException(status_code=404, detail=f"菜谱 ID '{recipe_id}' 不存在")
    return recipe


@router.put("/{recipe_id}", response_model=RecipeResponse)
async def update_recipe(
    recipe_id: str,
    recipe_update: RecipeUpdate,
    db: Session = Depends(get_db),
):
    """更新菜谱信息"""
    try:
        db_recipe = RecipeService.update_recipe(db, recipe_id, recipe_update)
        return db_recipe
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/{recipe_id}", status_code=204)
async def delete_recipe(
    recipe_id: str,
    db: Session = Depends(get_db),
):
    """删除菜谱"""
    try:
        RecipeService.delete_recipe(db, recipe_id)
        return None
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/categories/list", response_model=List[CategoryResponse])
async def get_categories(db: Session = Depends(get_db)):
    """
    获取所有菜谱分类（含中文名称）
    
    返回分类列表，每个分类包含:
    - key: 分类标识符
    - label: 中文名称
    
    前端可缓存此数据用于分类显示和筛选
    """
    categories = RecipeService.get_categories(db)
    
    result = []
    for key in categories:
        result.append(CategoryResponse(
            key=key,
            label=CATEGORY_NAMES.get(key, key),
        ))
    
    return result


@router.post("/batch", response_model=List[RecipeResponse], status_code=201)
async def create_recipes_batch(
    recipes: List[RecipeCreate],
    db: Session = Depends(get_db),
):
    """批量创建菜谱"""
    created_recipes = RecipeService.create_recipes_batch(db, recipes)
    return created_recipes

