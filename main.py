"""
============================================================
涉敏舆情数据加密传输与API安全防护系统
主应用入口
============================================================

【系统概述】
本系统采用FastAPI框架，实现涉敏舆情数据的加密传输与安全防护。
提供10大核心功能模块：
1. AES-256-GCM对称加密
2. RSA-2048数字签名
3. SHA-256/384/512哈希计算
4. 涉敏舆情数据加密存储
5. 第三方API安全调用
6. 数据流转审批流程
7. 涉敏字段脱敏策略
8. 攻击防御演示
9. 安全态势仪表盘
10. 审计日志追溯

【安全架构】（7层防护）
第1层：网络层 - HTTPS传输、安全HTTP头、CORS限制
第2层：请求层 - Nonce防重放、限流防护、CSRF验证
第3层：认证层 - JWT令牌、Refresh机制
第4层：权限层 - RBAC角色控制
第5层：数据层 - AES加密、RSA签名、哈希校验
第6层：展示层 - 数据脱敏、敏感词过滤
第7层：审计层 - 操作日志、安全事件记录

【技术栈】
- FastAPI：高性能异步Web框架
- SQLAlchemy：异步ORM数据库
- Cryptography：加密库（AES、RSA、SHA）
- PyJWT：JWT令牌处理
- Uvicorn：ASGI服务器

【运行方式】
python app.py  # 一键启动（自动安装依赖、启动服务）
============================================================
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from contextlib import asynccontextmanager
import uuid

from config import settings
from database import engine, Base
from auth.auth_router import router as auth_router
from routers.user_router import router as user_router
from routers.security_router import router as security_router
from routers.opinion_router import router as opinion_router
from security.replay import replay_protection
from security.headers import security_headers
from security.rate_limiter import setup_rate_limiter
from security.csrf import CsrfProtectionMiddleware
from utils.logger import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    应用生命周期管理
    
    启动阶段：
    - 初始化数据库表结构
    - 创建所有表（如果不存在）
    
    关闭阶段：
    - 清理资源
    - 关闭数据库连接
    """
    logger.info("Starting application")
    
    # 创建数据库表
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield  # 应用运行期间
    
    logger.info("Shutting down application")


# 创建FastAPI应用实例
app = FastAPI(
    title="涉敏舆情数据加密传输与API安全防护系统",
    description="信息安全综合设计课程设计 - 针对涉敏舆情数据提供加密传输、第三方API安全调用、内部流转防护的完整解决方案",
    version="3.0.0",
    lifespan=lifespan
)

# 第1层防护：限流防护（防止DDoS攻击）
# 限制：10秒内最多15次请求
setup_rate_limiter(app)

# 第1层防护：CORS跨域限制（防止跨域攻击）
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,  # 允许的源
    allow_credentials=True,               # 允许携带Cookie
    allow_methods=["*"],                  # 允许的HTTP方法
    allow_headers=["*"],                  # 允许的HTTP头
)

# 第2层防护：CSRF防护（防止跨站请求伪造）
app.add_middleware(CsrfProtectionMiddleware)

# 第2层防护：Nonce防重放（防止重放攻击）
app.middleware("http")(replay_protection)

# 第1层防护：安全HTTP头（防止信息泄露）
app.middleware("http")(security_headers)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    全局异常处理
    
    功能：
    - 捕获所有未处理异常
    - 记录错误日志
    - 返回统一错误格式
    
    返回格式：
    {
        "status": 500,
        "message": "错误描述",
        "request_id": "唯一追踪ID"
    }
    
    request_id作用：
    - 追踪错误来源
    - 便于排查问题
    """
    request_id = str(uuid.uuid4())
    logger.error(f"Unhandled exception: {exc}", extra={"request_id": request_id})
    
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status": exc.status_code,
                "message": exc.detail,
                "request_id": request_id
            }
        )
    
    return JSONResponse(
        status_code=500,
        content={
            "status": 500,
            "message": "Internal server error",
            "request_id": request_id
        }
    )


# 静态文件路由（前端界面）
app.mount("/static", StaticFiles(directory="static"), name="static")

# 注册API路由
app.include_router(auth_router)        # 认证路由
app.include_router(user_router)        # 用户路由
app.include_router(security_router)    # 安全路由（加密、签名、哈希）
app.include_router(opinion_router)     # 舆情路由（舆情加密、流转）


@app.get("/dashboard")
async def dashboard():
    """
    前端界面入口
    
    返回：
    - 静态HTML文件（毕业论文展示界面）
    
    界面内容：
    - 系统架构说明
    - 10大功能模块
    - 每个模块包含：原理说明、流程图、操作区、结果展示
    """
    return FileResponse("static/index.html")


@app.get("/health")
async def health_check():
    """
    健康检查接口
    
    用途：
    - 监控系统状态
    - 负载均衡判断
    - 自动化测试验证
    
    返回：
    {"status": "healthy"}
    """
    return {"status": "healthy"}


@app.get("/api/stats/attacks")
async def get_attack_stats():
    """
    攻击统计接口
    
    用途：
    - 前端仪表盘展示
    - 安全态势分析
    
    返回：
    {
        "total_blocked": 50,        # 总拦截次数
        "replay_blocked": 10,       # 重放攻击拦截
        "rate_limit_blocked": 30,   # 限流拦截
        "csrf_blocked": 10          # CSRF拦截
    }
    """
    from utils.attack_counter import attack_counter
    return attack_counter.get_stats()


if __name__ == "__main__":
    import uvicorn
    # 直接运行：uvicorn main:app --host 127.0.0.1 --port 8006
    uvicorn.run(app, host="127.0.0.1", port=8006)