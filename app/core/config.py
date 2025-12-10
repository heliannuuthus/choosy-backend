"""
应用配置管理
"""
from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    """应用配置"""
    
    # 应用信息
    APP_NAME: str = "Choosy API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # 服务器配置
    HOST: str = "0.0.0.0"
    PORT: int = 18000
    
    # 数据库配置
    DATABASE_URL: str = "sqlite:///./db/recipes.db"
    
    # CORS 配置
    CORS_ORIGINS: List[str] = ["*"]  # 开发环境允许所有来源，生产环境应限制具体域名
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]
    
    DASHSCOPE_API_KEY: str = os.getenv("DASHSCOPE_API_KEY")
    
    class Config:
        env_file = ".env"
        extra = "ignore"


# 创建全局配置实例
settings = Settings()

