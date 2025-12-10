"""
菜谱业务逻辑层
"""
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from app.models.recipe import Recipe, Ingredient, Step, AdditionalNote
from app.schemas.recipe import RecipeCreate, RecipeUpdate


class RecipeService:
    """菜谱服务类"""
    
    @staticmethod
    def create_recipe(db: Session, recipe: RecipeCreate) -> Recipe:
        """创建菜谱"""
        # 检查 ID 是否已存在
        existing = db.query(Recipe).filter(Recipe.id == recipe.id).first()
        if existing:
            raise ValueError(f"菜谱 ID '{recipe.id}' 已存在")
        
        # 创建菜谱主记录
        db_recipe = Recipe(
            id=recipe.id,
            name=recipe.name,
            description=recipe.description,
            source_path=recipe.source_path,
            image_path=recipe.image_path,
            images=recipe.images,
            category=recipe.category,
            difficulty=recipe.difficulty,
            tags=recipe.tags,
            servings=recipe.servings,
            prep_time_minutes=recipe.prep_time_minutes,
            cook_time_minutes=recipe.cook_time_minutes,
            total_time_minutes=recipe.total_time_minutes,
        )
        
        # 添加食材
        for ing in recipe.ingredients:
            db_ingredient = Ingredient(
                recipe_id=recipe.id,
                name=ing.name,
                quantity=ing.quantity,
                unit=ing.unit,
                text_quantity=ing.text_quantity,
                notes=ing.notes,
            )
            db_recipe.ingredients.append(db_ingredient)
        
        # 添加步骤
        for step in recipe.steps:
            db_step = Step(
                recipe_id=recipe.id,
                step=step.step,
                description=step.description,
            )
            db_recipe.steps.append(db_step)
        
        # 添加小贴士
        for note in recipe.additional_notes:
            db_note = AdditionalNote(
                recipe_id=recipe.id,
                note=note,
            )
            db_recipe.additional_notes.append(db_note)
        
        db.add(db_recipe)
        db.commit()
        db.refresh(db_recipe)
        
        return db_recipe
    
    @staticmethod
    def get_recipe(db: Session, recipe_id: str) -> Optional[Recipe]:
        """根据 ID 获取菜谱"""
        return db.query(Recipe).filter(Recipe.id == recipe_id).first()
    
    @staticmethod
    def get_recipes(
        db: Session,
        category: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Recipe]:
        """获取菜谱列表"""
        query = db.query(Recipe)
        
        # 按分类筛选
        if category:
            query = query.filter(Recipe.category == category)
        
        # 搜索筛选
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                or_(
                    Recipe.name.like(search_pattern),
                    Recipe.description.like(search_pattern),
                )
            )
        
        # 分页
        return query.offset(offset).limit(limit).all()
    
    @staticmethod
    def update_recipe(db: Session, recipe_id: str, recipe_update: RecipeUpdate) -> Recipe:
        """更新菜谱"""
        db_recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
        if not db_recipe:
            raise ValueError(f"菜谱 ID '{recipe_id}' 不存在")
        
        # 更新基本字段
        update_data = recipe_update.model_dump(
            exclude_unset=True,
            exclude={"ingredients", "steps", "additional_notes"}
        )
        for field, value in update_data.items():
            setattr(db_recipe, field, value)
        
        # 更新食材（如果提供）
        if recipe_update.ingredients is not None:
            db.query(Ingredient).filter(Ingredient.recipe_id == recipe_id).delete()
            for ing in recipe_update.ingredients:
                db_ingredient = Ingredient(
                    recipe_id=recipe_id,
                    name=ing.name,
                    quantity=ing.quantity,
                    unit=ing.unit,
                    text_quantity=ing.text_quantity,
                    notes=ing.notes,
                )
                db_recipe.ingredients.append(db_ingredient)
        
        # 更新步骤（如果提供）
        if recipe_update.steps is not None:
            db.query(Step).filter(Step.recipe_id == recipe_id).delete()
            for step in recipe_update.steps:
                db_step = Step(
                    recipe_id=recipe_id,
                    step=step.step,
                    description=step.description,
                )
                db_recipe.steps.append(db_step)
        
        # 更新小贴士（如果提供）
        if recipe_update.additional_notes is not None:
            db.query(AdditionalNote).filter(AdditionalNote.recipe_id == recipe_id).delete()
            for note in recipe_update.additional_notes:
                db_note = AdditionalNote(
                    recipe_id=recipe_id,
                    note=note,
                )
                db_recipe.additional_notes.append(db_note)
        
        db.commit()
        db.refresh(db_recipe)
        
        return db_recipe
    
    @staticmethod
    def delete_recipe(db: Session, recipe_id: str) -> bool:
        """删除菜谱"""
        db_recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
        if not db_recipe:
            raise ValueError(f"菜谱 ID '{recipe_id}' 不存在")
        
        db.delete(db_recipe)
        db.commit()
        
        return True
    
    @staticmethod
    def get_categories(db: Session) -> List[str]:
        """获取所有分类"""
        categories = db.query(Recipe.category).distinct().all()
        return [cat[0] for cat in categories if cat[0]]
    
    @staticmethod
    def get_categories_with_count(db: Session) -> Dict[str, int]:
        """获取所有分类及其菜谱数量"""
        results = db.query(
            Recipe.category,
            func.count(Recipe.id)
        ).group_by(Recipe.category).all()
        
        return {cat: count for cat, count in results if cat}
    
    @staticmethod
    def create_recipes_batch(db: Session, recipes: List[RecipeCreate]) -> List[Recipe]:
        """批量创建菜谱"""
        created_recipes = []
        
        for recipe in recipes:
            try:
                # 检查 ID 是否已存在
                existing = db.query(Recipe).filter(Recipe.id == recipe.id).first()
                if existing:
                    continue
                
                # 创建菜谱
                db_recipe = RecipeService.create_recipe(db, recipe)
                created_recipes.append(db_recipe)
            except Exception:
                # 跳过失败的记录
                continue
        
        return created_recipes

