"""
============================================================
RSA-2048 数字签名模块
============================================================

【原理说明】
RSA是非对称加密算法，核心特点是公钥加密、私钥解密（或私钥签名、公钥验签）。
数字签名用于验证数据完整性和来源真实性。

核心技术特性：
1. 密钥长度：2048位（256字节），破解难度极高
2. 非对称加密：公钥公开，私钥保密
   - 私钥签名：只有持有者能生成签名
   - 公钥验签：任何人都能验证签名真实性
3. PSS签名方案：Probabilistic Signature Scheme
   - 随机盐值：每次签名不同，防止签名分析攻击
   - 填充方案：增强安全性，符合RFC 3447标准
4. SHA-256哈希：签名前先对数据哈希，提高效率

【签名原理】
签名过程：
数据 → SHA-256哈希 → 私钥加密哈希值 → 生成数字签名

验签过程：
签名 → 公钥解密 → 得到哈希值 → 与原始数据哈希比对 → 验证通过/失败

【应用场景】
- API请求签名：防止请求被篡改或伪造
- 电子合同签署：保证签署者身份真实
- 软件分发验证：确保软件未被篡改
- 区块链交易签名：比特币、以太坊等

【安全优势】
- 不可伪造：只有私钥持有者能生成签名
- 不可篡改：数据修改会导致验签失败
- 可追溯：签名者身份可验证
- 雪崩效应：数据微小变化导致签名完全不同

【与AES对比】
AES（对称加密）：
- 加密解密用同一密钥
- 速度快，适合大量数据加密
- 用于数据保密

RSA（非对称加密）：
- 公钥私钥不同
- 速度慢，适合少量数据签名
- 用于身份认证、数据完整性
============================================================
"""

import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from config import settings


class SignatureService:
    """
    RSA-2048 数字签名服务类
    
    核心功能：
    - sign()：用私钥对数据签名，生成数字签名
    - verify()：用公钥验证签名，确认数据完整性
    - get_public_key_pem()：导出公钥，供验签方使用
    - hash_data()：计算数据哈希值（SHA-256/SHA-512/MD5）
    
    密钥管理：
    - private_key：私钥（保密，用于签名）
    - public_key：公钥（公开，用于验签）
    """
    
    def __init__(self):
        """
        初始化签名服务
        
        步骤：
        1. 生成RSA-2048密钥对（公钥+私钥）
        2. 公钥可公开，用于验签
        3. 私钥保密，用于签名
        """
        self.private_key = None
        self.public_key = None
        self._generate_keys()
    
    def _generate_keys(self):
        """
        生成RSA-2048密钥对
        
        参数：
            public_exponent：公钥指数，固定为65537（标准值）
            key_size：密钥长度，2048位（安全强度）
        
        原理：
            RSA密钥包含两个素数p、q
            n = p * q（2048位）
            公钥：(n, e)  e=65537
            私钥：(n, d)  d由e、p、q计算得出
        
        安全：
            2048位密钥破解难度：10^113次运算
            实际破解时间：数百年
        """
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,   # 标准公钥指数
                key_size=2048,           # 2048位密钥长度
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
        except Exception as e:
            print(f"密钥生成失败: {e}")
            raise
    
    def sign(self, data: str) -> str:
        """
        RSA数字签名函数
        
        参数：
            data：待签名的数据字符串
        
        返回：
            signature：Base64编码的数字签名
        
        核心步骤：
        1. 数据转为字节
        2. 使用PSS填充方案（Probabilistic Signature Scheme）
           - 随机盐值：每次签名不同
           - 增强安全性：防止签名分析攻击
        3. SHA-256哈希：签名前先对数据哈希
           - 原因：RSA签名数据长度受限（≤245字节）
           - 解决：哈希后固定长度32字节
        4. 私钥签名：用私钥加密哈希值
        5. Base64编码：便于传输和存储
        
        安全特性：
        - 不可伪造：只有私钥持有者能生成
        - 防篡改：数据修改会导致验签失败
        """
        try:
            # 步骤1：数据转为字节
            data_bytes = data.encode('utf-8')
            
            # 步骤2-4：私钥签名（使用PSS填充 + SHA-256哈希）
            signature = self.private_key.sign(
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),  # Mask Generation Function
                    salt_length=padding.PSS.MAX_LENGTH  # 最大盐值长度
                ),
                hashes.SHA256()  # 签名前先哈希
            )
            
            # 步骤5：Base64编码
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            print(f"签名失败: {e}")
            raise ValueError(f"签名失败: {str(e)}")
    
    def verify(self, data: str, signature: str) -> bool:
        """
        RSA签名验证函数
        
        参数：
            data：原始数据字符串
            signature：Base64编码的数字签名
        
        返回：
            True：验签通过，数据未被篡改
            False：验签失败，数据可能被篡改
        
        核心步骤：
        1. 解码签名（Base64 → 字节）
        2. 公钥解密签名，得到哈希值
        3. 计算原始数据的SHA-256哈希
        4. 比对两个哈希值
           - 相同：验签通过，数据完整
           - 不同：验签失败，数据被篡改
        
        应用场景：
        - API请求验签：确认请求未被篡改
        - 电子合同验签：确认签署者身份
        - 软件分发验签：确认软件完整性
        """
        try:
            # 步骤1：解码签名
            data_bytes = data.encode('utf-8')
            signature_bytes = base64.b64decode(signature)
            
            # 步骤2-4：公钥验签（使用PSS填充 + SHA-256哈希）
            self.public_key.verify(
                signature_bytes,
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # 验签通过
            return True
        except Exception as e:
            # 验签失败：数据可能被篡改，或签名伪造
            print(f"签名验证失败: {e}")
            return False
    
    def get_public_key_pem(self) -> str:
        """
        导出公钥（PEM格式）
        
        返回：
            PEM格式公钥字符串
            例如：
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
            -----END PUBLIC KEY-----
        
        应用：
        - 第三方验签：将公钥提供给验签方
        - API文档：在API文档中公开公钥
        - 客户端集成：客户端使用公钥验签
        
        PEM格式：
        - 标准公钥格式（Privacy Enhanced Mail）
        - Base64编码 + 标头标尾
        - 可直接存储在文本文件中
        """
        try:
            # 导出PEM格式公钥
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem.decode('utf-8')
        except Exception as e:
            print(f"导出公钥失败: {e}")
            raise
    
    def hash_data(self, data: str, algorithm: str = 'sha256') -> str:
        """
        数据哈希计算函数
        
        参数：
            data：待哈希的数据字符串
            algorithm：哈希算法（sha256/sha384/sha512/md5）
        
        返回：
            hash_value：哈希值（十六进制字符串）
        
        原理说明：
        哈希函数是将任意长度数据映射为固定长度值的单向函数。
        
        核心特性：
        1. 单向性：哈希值无法反推原始数据
        2. 抗碰撞：难以找到产生相同哈希的两个不同数据
        3. 雪崩效应：输入微小变化导致输出巨大差异
        4. 固定长度：SHA-256固定32字节，SHA-512固定64字节
        
        算法对比：
        - SHA-256：安全，推荐使用，32字节哈希值
        - SHA-384：更安全，48字节哈希值
        - SHA-512：最安全，64字节哈希值
        - MD5：不安全，已破解，仅用于兼容旧系统
        
        应用场景：
        - 密码存储：存储哈希值而非明文密码
        - 文件校验：验证文件完整性
        - 区块链：比特币区块哈希
        - 数字签名：签名前先哈希
        """
        try:
            data_bytes = data.encode('utf-8')
            
            # 选择哈希算法
            if algorithm.lower() == 'sha256':
                # SHA-256：最常用，安全强度高
                return hashlib.sha256(data_bytes).hexdigest()
            elif algorithm.lower() == 'sha384':
                # SHA-384：更高安全强度
                return hashlib.sha384(data_bytes).hexdigest()
            elif algorithm.lower() == 'sha512':
                # SHA-512：最高安全强度
                return hashlib.sha512(data_bytes).hexdigest()
            elif algorithm.lower() == 'md5':
                # MD5：不安全，已破解，仅用于兼容
                return hashlib.md5(data_bytes).hexdigest()
            else:
                raise ValueError(f"不支持的哈希算法: {algorithm}")
        except Exception as e:
            print(f"哈希计算失败: {e}")
            raise ValueError(f"哈希计算失败: {str(e)}")


# 创建全局签名服务实例
signature_service = SignatureService()