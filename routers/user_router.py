from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from security.encryption import encryption_service
from security.mask import mask_sensitive_data, mask_phone, mask_id_card, mask_bank_card, mask_email

router = APIRouter(prefix="/api/users", tags=["users"])

class EncryptRequest(BaseModel):
    data: str
    field_type: str = "default"

class DecryptRequest(BaseModel):
    encrypted: str

class EncryptResponse(BaseModel):
    encrypted: str
    masked: str

class DecryptResponse(BaseModel):
    decrypted: str

@router.get("/me")
async def get_current_user_profile():
    """获取当前用户信息（演示模式）"""
    return {
        "id": 0,
        "username": "demo_user",
        "email": mask_email("demo@example.com"),
        "full_name": "演示用户",
        "role": "user",
        "is_active": True,
        "phone": mask_phone("13800138000"),
        "id_card": mask_id_card("110101199001011234"),
        "bank_card": mask_bank_card("6222021234567890123")
    }

@router.get("/me/masked")
async def get_masked_user_profile():
    """获取脱敏后的用户信息"""
    return {
        "id": 0,
        "username": "demo_user",
        "email": mask_email("demo@example.com"),
        "full_name": "演示用户",
        "role": "user",
        "is_active": True,
        "phone": mask_phone("13800138000"),
        "id_card": mask_id_card("110101199001011234"),
        "bank_card": mask_bank_card("6222021234567890123")
    }

@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt_data(encrypt_data: EncryptRequest):
    """加密敏感数据"""
    encrypted = encryption_service.encrypt(encrypt_data.data)
    masked = mask_sensitive_data(encrypt_data.data, encrypt_data.field_type)
    return EncryptResponse(encrypted=encrypted, masked=masked)

@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt_data(decrypt_data: DecryptRequest):
    """解密敏感数据"""
    try:
        decrypted = encryption_service.decrypt(decrypt_data.encrypted)
        return DecryptResponse(decrypted=decrypted)
    except Exception as e:
        raise HTTPException(status_code=400, detail="解密失败：数据格式错误或密钥不匹配")