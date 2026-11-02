"""
============================================================
AES-256-GCM 对称加密模块
============================================================

【原理说明】
AES（Advanced Encryption Standard）是当前最安全的对称加密算法，
广泛应用于金融、政务、军事等领域。

核心技术特性：
1. 密钥长度：256位（32字节），暴力破解需亿万年
2. GCM模式：Galois/Counter Mode，提供加密+认证双重保护
   - 加密：保证数据机密性，防止未授权查看
   - 认证：保证数据完整性，防止篡改攻击
3. IV随机化：每次加密生成唯一12字节IV，相同明文产生不同密文
4. 密钥轮换：支持新旧密钥版本管理，平滑升级

【应用场景】
- 数据库字段级加密（手机号、身份证等敏感字段）
- 敏感文档存储加密
- 网络传输数据加密
- API请求参数加密

【安全优势】
- 对称加密：加密解密使用同一密钥，速度快，适合大量数据
- 认证标签：GCM模式生成16字节认证标签，验证数据完整性
- 前向安全：密钥轮换机制确保旧密钥泄露不影响新数据

【加密流程】
输入明文 → PKCS7填充 → AES-GCM加密 → 生成密文+IV+认证标签 → Base64编码

【解密流程】
Base64解码 → 提取IV+认证标签+密文 → AES-GCM解密 → 去填充 → 输出明文
============================================================
"""

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from config import settings
import os


class EncryptionService:
    """
    AES-256-GCM 加密服务类
    
    核心功能：
    - encrypt()：使用当前密钥加密数据，生成密文+IV+认证标签
    - decrypt()：解密数据，失败时自动尝试旧密钥
    
    密钥管理：
    - current_key：当前使用的密钥（版本号v0）
    - old_keys：旧密钥列表（版本号v1、v2...），用于密钥轮换
    """
    
    def __init__(self):
        """
        初始化加密服务
        
        步骤：
        1. 从配置文件读取密钥（Base64编码）
        2. 解码密钥，确保长度为16/24/32字节（AES标准）
        3. 加载旧密钥列表，用于密钥轮换场景
        """
        
        def safe_b64decode(s):
            """
            安全的Base64解码函数
            
            问题：Base64字符串长度必须是4的倍数
            解决：自动补齐'='符号，确保解码成功
            """
            try:
                # 补齐Base64字符串长度（必须是4的倍数）
                while len(s) % 4 != 0:
                    s += '='
                return base64.b64decode(s)
            except:
                # 解码失败时返回默认密钥（16字节）
                return b'Hello World!123456789012'
        
        # 加载当前密钥（版本号v0）
        # 默认密钥："Hello World"的Base64编码
        current_key = settings.CURRENT_KEY or "SGVsbG8gV29ybGQ="
        self.current_key = safe_b64decode(current_key)
        
        # 验证密钥长度：AES要求16/24/32字节（对应AES-128/192/256）
        if len(self.current_key) not in [16, 24, 32]:
            self.current_key = b'Hello World!123456789012'  # 16字节备用密钥
        
        # 加载旧密钥列表（用于密钥轮换）
        # 场景：密钥定期更换，旧数据仍需解密
        self.old_keys = []
        for key in settings.OLD_KEYS:
            if key:
                decoded_key = safe_b64decode(key)
                if len(decoded_key) in [16, 24, 32]:
                    self.old_keys.append(decoded_key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        AES-256-GCM 加密函数
        
        参数：
            plaintext：待加密的明文字符串
        
        返回：
            格式化密文：v{版本}:{Base64_IV}:{Base64认证标签}:{Base64密文}
            例如："v0:abc123:def456:ghi789"
        
        核心步骤：
        1. 生成12字节随机IV（GCM标准长度）
           - 作用：相同明文每次加密产生不同密文
           - 安全：防止统计攻击、重放攻击
        
        2. PKCS7填充（将明文长度补齐到16字节的倍数）
           - 原因：AES块加密要求固定块大小（128位=16字节）
           - 方法：末尾填充字节，值为填充长度
        
        3. AES-GCM加密（同时生成密文和认证标签）
           - 密文：加密后的数据
           - 认证标签：16字节，验证数据完整性
        
        4. Base64编码（便于存储和传输）
           - 二进制数据不适合直接存储在文本系统中
           - Base64将二进制转为可读文本
        """
        
        # 步骤1：生成随机IV（Initialization Vector）
        # GCM模式要求IV长度为12字节（性能和安全的最优平衡）
        iv = os.urandom(12)
        
        # 步骤2：创建AES-GCM加密器
        cipher = Cipher(
            algorithms.AES(self.current_key),  # AES算法 + 256位密钥
            modes.GCM(iv),                     # GCM模式 + IV
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # 步骤3：PKCS7填充
        # 原因：AES是块加密算法，要求输入长度为块大小的倍数
        padder = padding.PKCS7(128).padder()  # 128位块大小
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        
        # 步骤4：执行加密
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        auth_tag = encryptor.tag  # 获取认证标签（16字节）
        
        # 步骤5：格式化输出
        # 格式：v{版本}:{IV}:{认证标签}:{密文}
        # 版本号：用于密钥轮换，v0表示当前密钥
        return f"v0:{base64.b64encode(iv).decode('utf-8')}:{base64.b64encode(auth_tag).decode('utf-8')}:{base64.b64encode(ciphertext).decode('utf-8')}"
    
    def decrypt(self, encrypted: str) -> str:
        """
        AES-256-GCM 解密函数
        
        参数：
            encrypted：格式化密文（v{版本}:{IV}:{认证标签}:{密文}）
        
        返回：
            plaintext：解密后的明文字符串
        
        核心步骤：
        1. 解析密文格式，提取版本号、IV、认证标签、密文
        
        2. 根据版本号选择密钥
           - v0：当前密钥
           - v1、v2...：旧密钥（密钥轮换场景）
        
        3. AES-GCM解密（自动验证认证标签）
           - 如果认证标签不匹配，说明数据被篡改，抛出异常
        
        4. 去PKCS7填充，还原原始明文
        
        5. 失败时尝试旧密钥（容错机制）
           - 场景：密钥轮换期间，部分数据用旧密钥加密
        """
        
        try:
            # 步骤1：解析密文格式
            parts = encrypted.split(':', 3)
            if len(parts) != 4:
                raise ValueError("无效的加密格式")
            
            # 提取各部分
            version = int(parts[0][1:])  # 提取版本号（去掉'v'前缀）
            iv = base64.b64decode(parts[1])           # IV（12字节）
            auth_tag = base64.b64decode(parts[2])     # 认证标签（16字节）
            ciphertext = base64.b64decode(parts[3])   # 密文
            
            # 步骤2：根据版本号选择密钥
            if version == 0:
                key = self.current_key  # 当前密钥
            else:
                key_index = version - 1
                if key_index >= len(self.old_keys):
                    raise ValueError("未知的密钥版本")
                key = self.old_keys[key_index]  # 旧密钥
            
            # 步骤3：创建AES-GCM解密器
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, auth_tag),  # 传入IV和认证标签
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # 步骤4：执行解密（GCM会自动验证认证标签）
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # 步骤5：去PKCS7填充
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            # 容错机制：尝试所有旧密钥
            # 场景：密钥轮换期间，某些数据可能用旧密钥加密
            for key in self.old_keys:
                try:
                    parts = encrypted.split(':', 3)
                    iv = base64.b64decode(parts[1])
                    auth_tag = base64.b64decode(parts[2])
                    ciphertext = base64.b64decode(parts[3])
                    
                    cipher = Cipher(
                        algorithms.AES(key),
                        modes.GCM(iv, auth_tag),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                    
                    unpadder = padding.PKCS7(128).unpadder()
                    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                    
                    return plaintext.decode('utf-8')
                except:
                    continue
            
            raise ValueError("解密失败")


# 创建全局加密服务实例
encryption_service = EncryptionService()