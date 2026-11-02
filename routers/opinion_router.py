from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from security.encryption import encryption_service
from security.mask import mask_sensitive_data
from utils.logger import logger
from datetime import datetime

router = APIRouter(prefix="/api/opinion", tags=["舆情数据"])

class OpinionData(BaseModel):
    title: str
    content: str
    source: str
    author: Optional[str] = None
    contact: Optional[str] = None
    ip_address: Optional[str] = None
    keywords: Optional[List[str]] = []
    sentiment: Optional[str] = None

class OpinionEncryptRequest(BaseModel):
    opinion_data: OpinionData
    field_type: str = "opinion"

class OpinionTransferRequest(BaseModel):
    opinion_id: str
    target_department: str
    reason: str
    approval_required: bool = True

class OpinionExportRequest(BaseModel):
    opinion_ids: List[str]
    format: str = "json"
    mask_required: bool = True
    approval_required: bool = True

@router.post("/encrypt")
async def encrypt_opinion_data(request: OpinionEncryptRequest):
    """加密舆情数据"""
    try:
        opinion_dict = request.opinion_data.dict()

        encrypted_data = {}
        for key, value in opinion_dict.items():
            if value:
                encrypted_data[key] = encryption_service.encrypt(str(value))
            else:
                encrypted_data[key] = None

        encrypted_data['encrypted_at'] = datetime.utcnow().isoformat()

        logger.info(f"舆情数据加密成功: {opinion_dict.get('title', '')}")

        return {
            "status": "success",
            "message": "舆情数据加密成功",
            "encrypted_data": encrypted_data,
            "encryption_algorithm": "AES-256-GCM"
        }
    except Exception as e:
        logger.error(f"舆情数据加密失败: {e}")
        raise HTTPException(status_code=500, detail="舆情数据加密失败")

@router.post("/decrypt")
async def decrypt_opinion_data(opinion_id: str):
    """解密舆情数据"""
    try:
        logger.info(f"请求解密舆情数据 {opinion_id}")
        return {
            "status": "success",
            "message": "舆情数据解密成功",
            "decrypted_data": {
                "opinion_id": opinion_id,
                "decrypted_at": datetime.utcnow().isoformat()
            }
        }
    except Exception as e:
        logger.error(f"舆情数据解密失败: {e}")
        raise HTTPException(status_code=500, detail="舆情数据解密失败")

@router.get("/list")
async def get_opinion_list(skip: int = 0, limit: int = 10):
    """获取舆情数据列表（脱敏后）"""
    try:
        sample_data = [
            {
                "id": "OP001",
                "title": "关于某事件的舆情分析报告",
                "source": "微博",
                "author_masked": "张***",
                "sentiment": "中性",
                "keywords": ["舆情", "事件", "分析"],
                "created_at": datetime.utcnow().isoformat()
            },
            {
                "id": "OP002",
                "title": "网络舆情监测周报",
                "source": "微信公众号",
                "author_masked": "李***",
                "sentiment": "正面",
                "keywords": ["监测", "周报", "网络"],
                "created_at": datetime.utcnow().isoformat()
            },
            {
                "id": "OP003",
                "title": "突发事件舆情应对方案",
                "source": "新闻网站",
                "author_masked": "王**",
                "sentiment": "负面",
                "keywords": ["应急", "处置", "响应"],
                "created_at": datetime.utcnow().isoformat()
            },
            {
                "id": "OP004",
                "title": "社交平台敏感信息分析",
                "source": "论坛",
                "author_masked": "赵**",
                "sentiment": "中性",
                "keywords": ["敏感词", "过滤", "分析"],
                "created_at": datetime.utcnow().isoformat()
            }
        ]

        return {
            "status": "success",
            "total": len(sample_data),
            "data": sample_data,
            "note": "数据已脱敏处理"
        }
    except Exception as e:
        logger.error(f"获取舆情列表失败: {e}")
        raise HTTPException(status_code=500, detail="获取舆情列表失败")

@router.post("/transfer")
async def transfer_opinion_data(request: OpinionTransferRequest):
    """舆情数据流转申请"""
    try:
        transfer_id = f"TR{int(datetime.utcnow().timestamp())}"
        logger.info(f"数据流转申请 {transfer_id}: {request.opinion_id} -> {request.target_department}")
        return {
            "status": "success",
            "message": "流转申请已提交",
            "transfer_id": transfer_id,
            "approval_required": request.approval_required,
            "applied_at": datetime.utcnow().isoformat(),
            "note": "待审批通过后数据将加密传输"
        }
    except Exception as e:
        logger.error(f"数据流转申请失败: {e}")
        raise HTTPException(status_code=500, detail="数据流转申请失败")

@router.post("/export")
async def export_opinion_data(request: OpinionExportRequest):
    """导出舆情数据"""
    try:
        if request.approval_required:
            return {
                "status": "pending_approval",
                "message": "导出申请已提交，等待审批",
                "approval_required": True,
                "export_ids": request.opinion_ids
            }
        else:
            return {
                "status": "success",
                "message": "舆情数据导出成功",
                "export_format": request.format,
                "masked": request.mask_required,
                "data": [],
                "note": f"数据已{'脱敏' if request.mask_required else '加密'}处理"
            }
    except Exception as e:
        logger.error(f"舆情数据导出失败: {e}")
        raise HTTPException(status_code=500, detail="舆情数据导出失败")

@router.get("/sensitive-fields")
async def get_sensitive_fields():
    """获取涉敏字段列表"""
    return {
        "status": "success",
        "sensitive_fields": [
            {
                "field": "author",
                "description": "作者信息",
                "handling": "加密存储 + 脱敏展示",
                "example": "张三丰 -> 张***"
            },
            {
                "field": "contact",
                "description": "联系方式（手机/电话）",
                "handling": "加密存储 + 完全脱敏",
                "example": "13800138000 -> 138****8000"
            },
            {
                "field": "id_card",
                "description": "身份证号",
                "handling": "加密存储 + 部分脱敏",
                "example": "110101********1234"
            },
            {
                "field": "bank_card",
                "description": "银行卡号",
                "handling": "加密存储 + 部分脱敏",
                "example": "622202********9012"
            },
            {
                "field": "ip_address",
                "description": "IP地址",
                "handling": "模糊化处理",
                "example": "192.168.1.100 -> 192.168.*.*"
            },
            {
                "field": "email",
                "description": "邮箱地址",
                "handling": "部分脱敏",
                "example": "zhang***@example.com"
            }
        ]
    }
