"""
============================================================
安全功能路由模块
============================================================

【功能说明】
本模块提供加密、签名、哈希相关的API接口：
1. /api/security/sign - RSA数字签名
2. /api/security/verify - RSA签名验证
3. /api/security/hash - SHA哈希计算
4. /api/security/public-key - RSA公钥获取

【接口设计原则】
- 输入验证：使用Pydantic模型验证请求参数
- 错误处理：统一错误格式，便于调试
- 日志记录：记录关键操作，便于审计

【请求格式】
签名请求：
{
    "data": "待签名数据"
}

验签请求：
{
    "data": "原始数据",
    "signature": "数字签名"
}

哈希请求：
{
    "data": "待哈希数据",
    "algorithm": "sha256"  // sha256/sha384/sha512/md5
}

【响应格式】
成功响应：
{
    "data": "原始数据",
    "signature": "签名值",
    "algorithm": "RSA-PSS-SHA256"
}

错误响应：
HTTP 400/500 + {"detail": "错误描述"}
============================================================
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from security.signature import signature_service
from utils.logger import logger

# 创建路由器，路径前缀 /api/security
router = APIRouter(prefix="/api/security", tags=["security"])


class SignRequest(BaseModel):
    """
    签名请求模型
    
    参数：
    - data：待签名的数据字符串
    
    验证规则：
    - 必填字段
    - 自动验证类型
    """
    data: str


class VerifyRequest(BaseModel):
    """
    验签请求模型
    
    参数：
    - data：原始数据字符串
    - signature：Base64编码的数字签名
    
    验证规则：
    - 两者均必填
    - 签名必须是有效的Base64字符串
    """
    data: str
    signature: str


class HashRequest(BaseModel):
    """
    哈希请求模型
    
    参数：
    - data：待哈希的数据字符串
    - algorithm：哈希算法（默认sha256）
    
    支持算法：
    - sha256：最常用，推荐
    - sha384：更高安全强度
    - sha512：最高安全强度
    - md5：不安全，仅用于兼容
    """
    data: str
    algorithm: str = "sha256"


@router.post("/sign")
async def sign_data(request: SignRequest):
    """
    RSA数字签名接口
    
    功能：
    用私钥对数据进行签名，生成数字签名
    
    签名流程：
    数据 → SHA-256哈希 → RSA-PSS签名 → Base64编码
    
    返回：
    {
        "data": "原始数据",
        "signature": "签名值",
        "algorithm": "RSA-PSS-SHA256"
    }
    
    应用场景：
    - API请求签名：防止请求篡改
    - 电子合同签署：保证签署者身份
    - 数据完整性校验：确保数据未被修改
    """
    try:
        # 调用签名服务生成签名
        signature = signature_service.sign(request.data)
        
        # 记录日志（脱敏显示，只显示前20字符）
        logger.info(f"数字签名生成成功: {request.data[:20]}...")
        
        return {
            "data": request.data,
            "signature": signature,
            "algorithm": "RSA-PSS-SHA256"  # RSA + PSS填充 + SHA-256哈希
        }
    except Exception as e:
        # 记录错误日志
        logger.error(f"签名失败: {e}")
        raise HTTPException(status_code=500, detail="签名失败")


@router.post("/verify")
async def verify_signature(request: VerifyRequest):
    """
    RSA签名验证接口
    
    功能：
    用公钥验证签名，确认数据完整性
    
    验签流程：
    签名 → Base64解码 → 公钥解密 → 哈希比对 → 验证通过/失败
    
    返回：
    {
        "valid": true/false,
        "data": "原始数据",
        "algorithm": "RSA-PSS-SHA256"
    }
    
    验签结果：
    - valid=true：验签通过，数据未被篡改
    - valid=false：验签失败，数据可能被篡改或签名伪造
    
    安全意义：
    - 数据完整性：确保数据传输过程中未被修改
    - 来源真实性：确认签名者身份
    - 不可抵赖性：签名者无法否认签署行为
    """
    try:
        # 调用签名服务验证签名
        valid = signature_service.verify(request.data, request.signature)
        
        # 记录日志
        logger.info(f"签名验证完成: {valid}")
        
        return {
            "valid": valid,
            "data": request.data,
            "algorithm": "RSA-PSS-SHA256"
        }
    except Exception as e:
        # 记录错误日志
        logger.error(f"签名验证失败: {e}")
        raise HTTPException(status_code=500, detail="签名验证失败")


@router.post("/hash")
async def hash_data(request: HashRequest):
    """
    SHA哈希计算接口
    
    功能：
    计算数据的哈希值（不可逆加密）
    
    哈希流程：
    数据 → UTF-8编码 → SHA哈希 → 十六进制输出
    
    返回：
    {
        "data": "原始数据",
        "algorithm": "SHA-256",
        "hash": "哈希值（64位十六进制）"
    }
    
    哈希特性：
    - 单向性：哈希值无法反推原始数据
    - 抗碰撞：难以找到相同哈希的不同数据
    - 雪崩效应：输入微小变化导致哈希巨大差异
    
    应用场景：
    - 密码存储：存储哈希值而非明文
    - 文件校验：验证文件完整性
    - 区块链：比特币区块哈希
    """
    try:
        # 调用签名服务计算哈希
        hash_value = signature_service.hash_data(request.data, request.algorithm)
        
        return {
            "data": request.data,
            "algorithm": request.algorithm.upper(),  # 算法名称标准化
            "hash": hash_value
        }
    except ValueError as e:
        # 算法不支持错误（400错误）
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # 其他错误（500错误）
        logger.error(f"哈希计算失败: {e}")
        raise HTTPException(status_code=500, detail="哈希计算失败")


@router.get("/public-key")
async def get_public_key():
    """
    RSA公钥获取接口
    
    功能：
    获取RSA公钥（PEM格式），供第三方验签
    
    PEM格式：
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----
    
    返回：
    {
        "public_key": "PEM格式公钥字符串",
        "algorithm": "RSA-2048"
    }
    
    应用场景：
    - 第三方验签：将公钥提供给验签方
    - API文档：在文档中公开公钥
    - 客户端集成：客户端使用公钥验签
    
    安全说明：
    - 公钥可公开，无安全风险
    - 私钥保密，仅用于签名
    - 公钥只能验签，不能签名
    """
    try:
        # 获取PEM格式公钥
        pem = signature_service.get_public_key_pem()
        
        return {
            "public_key": pem,
            "algorithm": "RSA-2048"
        }
    except Exception as e:
        # 记录错误日志
        logger.error(f"获取公钥失败: {e}")
        raise HTTPException(status_code=500, detail="获取公钥失败")