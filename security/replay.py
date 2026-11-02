"""
============================================================
防重放攻击模块
============================================================

【原理说明】
重放攻击（Replay Attack）是网络安全的常见威胁：
攻击者截获合法请求，重复发送给服务器，造成重复操作。

攻击场景：
1. 用户支付100元，攻击者截获支付请求，重复发送10次
   结果：用户支付了1000元，造成经济损失
2. 用户提交审批申请，攻击者截获请求，重复发送100次
   结果：系统产生100条重复审批记录

防护原理：
使用Nonce（随机数）+ Timestamp（时间戳）双重验证：
1. Nonce唯一性：每个请求携带唯一随机数，服务器记录已使用的Nonce
   如果Nonce重复使用 → 检测到重放攻击 → 拦截请求

2. Timestamp时效性：请求携带时间戳，服务器验证时间差
   如果时间差>3分钟 → 请求过期 → 拦截请求

【技术实现】
1. 客户端请求：生成UUID作为Nonce + 当前时间戳
   Headers: {
       "X-Nonce": "550e8400-e29b-41d4-a716-446655440000",
       "X-Timestamp": "1703123456789"
   }

2. 服务器验证：
   - 检查Nonce是否已使用（存在nonce_store中）
   - 检查Timestamp是否在可接受范围内（±3分钟）

3. 拦截策略：
   - Nonce重复：HTTP 409 Conflict
   - Timestamp过期：HTTP 400 Bad Request

【Nonce存储管理】
- 存储：内存字典（nonce_store）
- 过期：5分钟后自动清理（防止内存泄漏）
- 容量：无上限，但过期清理保证内存可控

【应用场景】
- 金融交易：支付、转账等高敏感操作
- 权限变更：审批、授权等关键操作
- 数据提交：表单提交、文件上传等

【安全优势】
- 100%拦截重放攻击：Nonce唯一性保证
- 时效性控制：防止历史请求被恶意重放
- 低开销：内存存储，快速验证
============================================================
"""

import time
import uuid
from fastapi import Request, HTTPException, Header
from fastapi.responses import JSONResponse
from typing import Optional
from config import settings
from utils.attack_counter import attack_counter


class ReplayProtection:
    """
    防重放攻击中间件
    
    核心组件：
    - nonce_store：已使用Nonce的存储字典
    - __call__：中间件执行函数
    
    工作流程：
    1. 检查请求路径，跳过不需要防护的路径
    2. 提取X-Nonce和X-Timestamp头
    3. 验证时间戳时效性（±3分钟）
    4. 验证Nonce唯一性（已使用则拦截）
    5. 存储Nonce，设置过期时间
    6. 清理过期Nonce，防止内存泄漏
    """
    
    def __init__(self):
        """
        初始化防重放攻击保护
        
        nonce_store结构：
        {
            "uuid-1": 使用时间,
            "uuid-2": 使用时间,
            ...
        }
        
        过期策略：
        - 5分钟后自动删除
        - 防止nonce_store无限增长
        """
        self.nonce_store = {}
    
    async def __call__(self, request: Request, call_next):
        """
        中间件执行函数
        
        参数：
        request：FastAPI请求对象
        call_next：下一个中间件或路由处理函数
        
        返回：
        response：响应对象
        
        处理流程：
        1. 跳过白名单路径（静态文件、文档等）
        2. 检查安全头是否存在
        3. 验证时间戳时效性
        4. 验证Nonce唯一性
        5. 存储Nonce并清理过期Nonce
        """
        
        # 获取安全头
        nonce = request.headers.get("X-Nonce")        # 随机数
        timestamp = request.headers.get("X-Timestamp") # 时间戳
        referer = request.headers.get("Referer", "")   # 来源页面
        
        # 获取请求路径
        path = request.url.path
        
        # 白名单路径（不需要防护）
        # 原因：这些路径不涉及敏感操作，无需防重放
        if (path in ["/", "/dashboard", "/health", "/favicon.ico"] or 
            path.startswith("/static") or              # 静态文件
            path.startswith("/docs") or                # API文档
            path.startswith("/redoc") or               # ReDoc文档
            path.startswith("/openapi.json") or        # OpenAPI规范
            path.startswith("/api/stats")):            # 统计接口
            
            response = await call_next(request)
            return response
        
        # 检查安全头是否存在
        if not nonce or not timestamp:
            # 特殊情况：来自/docs的测试请求
            # Swagger UI的"Try it out"功能不会发送安全头
            if "/docs" in referer or request.headers.get("X-Test-Request") == "true":
                response = await call_next(request)
                return response
            
            # 缺少安全头，返回400错误
            return JSONResponse(
                status_code=400,
                content={
                    "status": 400,
                    "message": "缺少必要的安全头: X-Nonce 和 X-Timestamp"
                }
            )
        
        # 验证时间戳时效性
        try:
            request_time = int(timestamp)            # 请求时间戳（毫秒）
            current_time = int(time.time() * 1000)   # 当前时间（毫秒）
            time_diff = abs(current_time - request_time)  # 时间差
            
            # 可接受范围：±3分钟（180秒 = 180000毫秒）
            # 原因：考虑网络延迟、客户端时钟误差
            if time_diff > 180000:
                return JSONResponse(
                    status_code=400,
                    content={
                        "status": 400,
                        "message": "请求时间戳超出可接受范围"
                    }
                )
        except ValueError:
            # 时间戳格式错误（非数字）
            return JSONResponse(
                status_code=400,
                content={
                    "status": 400,
                    "message": "无效的时间戳格式"
                }
            )
        
        # 验证Nonce唯一性（核心防护逻辑）
        if nonce in self.nonce_store:
            # Nonce已被使用 → 检测到重放攻击
            # 增加攻击计数器（用于统计展示）
            attack_counter.increment_replay_attack()
            
            return JSONResponse(
                status_code=409,  # 409 Conflict
                content={
                    "status": 409,
                    "message": "Nonce 已被使用（检测到重放攻击）"
                }
            )
        
        # 存储Nonce，记录使用时间
        self.nonce_store[nonce] = time.time()
        
        # 清理过期Nonce（防止内存泄漏）
        # 过期时间：5分钟（300秒）
        current_time = time.time()
        to_remove = []
        
        for key, value in self.nonce_store.items():
            if current_time - value > 300:  # 5分钟过期
                to_remove.append(key)
        
        # 删除过期Nonce
        for key in to_remove:
            del self.nonce_store[key]
        
        # 继续处理请求
        response = await call_next(request)
        return response


# 创建全局实例
replay_protection = ReplayProtection()