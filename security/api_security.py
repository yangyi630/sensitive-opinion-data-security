import base64
import json
import time
import hashlib
from typing import Dict, Any, Optional
from security.signature import signature_service
from security.encryption import encryption_service

class APISecurityService:
    def __init__(self):
        """初始化API安全服务"""
        self.api_key_storage = {}
        self.call_history = []

    def generate_api_signature(self, endpoint: str, params: Dict[str, Any], api_key: str) -> Dict[str, str]:
        """
        生成API调用签名
        用于第三方API调用的请求签名
        """
        try:
            timestamp = str(int(time.time()))
            nonce = base64.b64encode(str(time.time()).encode()).decode()[:16]
            
            data_to_sign = {
                'endpoint': endpoint,
                'params': json.dumps(params, sort_keys=True),
                'timestamp': timestamp,
                'nonce': nonce,
                'api_key': api_key
            }
            
            data_string = '|'.join([str(v) for v in data_to_sign.values()])
            
            signature = signature_service.sign(data_string)
            
            return {
                'timestamp': timestamp,
                'nonce': nonce,
                'signature': signature,
                'api_key': api_key
            }
        except Exception as e:
            print(f"API签名生成失败: {e}")
            raise ValueError(f"API签名生成失败: {str(e)}")

    def verify_api_signature(self, endpoint: str, params: Dict[str, Any], 
                           timestamp: str, nonce: str, signature: str, api_key: str) -> bool:
        """
        验证API调用签名
        用于验证第三方API响应的签名
        """
        try:
            data_to_sign = {
                'endpoint': endpoint,
                'params': json.dumps(params, sort_keys=True),
                'timestamp': timestamp,
                'nonce': nonce,
                'api_key': api_key
            }
            
            data_string = '|'.join([str(v) for v in data_to_sign.values()])
            
            return signature_service.verify(data_string, signature)
        except Exception as e:
            print(f"API签名验证失败: {e}")
            return False

    def encrypt_api_request(self, data: Dict[str, Any]) -> str:
        """
        加密API请求数据
        用于敏感参数的加密传输
        """
        try:
            json_data = json.dumps(data)
            return encryption_service.encrypt(json_data)
        except Exception as e:
            print(f"API请求加密失败: {e}")
            raise ValueError(f"API请求加密失败: {str(e)}")

    def decrypt_api_response(self, encrypted_data: str) -> Dict[str, Any]:
        """
        解密API响应数据
        用于第三方API返回的加密数据解密
        """
        try:
            decrypted = encryption_service.decrypt(encrypted_data)
            return json.loads(decrypted)
        except Exception as e:
            print(f"API响应解密失败: {e}")
            raise ValueError(f"API响应解密失败: {str(e)}")

    def store_api_key(self, key_name: str, api_key: str, encrypted: bool = True):
        """
        安全存储API密钥
        """
        if encrypted:
            encrypted_key = encryption_service.encrypt(api_key)
            self.api_key_storage[key_name] = {
                'encrypted': True,
                'value': encrypted_key
            }
        else:
            self.api_key_storage[key_name] = {
                'encrypted': False,
                'value': api_key
            }

    def get_api_key(self, key_name: str) -> Optional[str]:
        """
        获取存储的API密钥
        """
        if key_name not in self.api_key_storage:
            return None
        
        key_info = self.api_key_storage[key_name]
        if key_info['encrypted']:
            try:
                return encryption_service.decrypt(key_info['value'])
            except:
                return None
        else:
            return key_info['value']

    def log_api_call(self, endpoint: str, params: Dict[str, Any], 
                    response_status: str, timestamp: str):
        """
        记录API调用日志
        """
        log_entry = {
            'endpoint': endpoint,
            'params_keys': list(params.keys()),
            'response_status': response_status,
            'timestamp': timestamp,
            'time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.call_history.append(log_entry)

    def get_api_call_history(self, limit: int = 100):
        """
        获取API调用历史
        """
        return self.call_history[-limit:]

    def calculate_request_hash(self, data: Dict[str, Any]) -> str:
        """
        计算请求数据哈希
        用于数据完整性校验
        """
        json_data = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_data.encode()).hexdigest()

    def validate_timestamp(self, timestamp: str, max_age_seconds: int = 300) -> bool:
        """
        验证时间戳有效性
        用于防止重放攻击
        """
        try:
            request_time = int(timestamp)
            current_time = int(time.time())
            age = current_time - request_time
            return 0 <= age <= max_age_seconds
        except:
            return False

api_security_service = APISecurityService()
