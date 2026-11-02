"""
============================================================
涉敏舆情数据加密传输与API安全防护系统
一键启动脚本
============================================================

【功能说明】
本脚本实现一键启动系统，自动完成：
1. Python版本检查（要求3.10+）
2. pip工具检查
3. 环境配置文件检查
4. 依赖包检测与自动安装
5. 服务启动与浏览器打开

【使用方式】
双击运行 app.py 或执行命令：python app.py

【适用场景】
- 演示环境快速部署
- 毕业论文答辩展示
- 测试环境搭建
- 无需手动配置的开发环境

【自动化特性】
- 自动检测缺失依赖
- 自动尝试多个镜像源（阿里云、中科大、华科、官方）
- 自动打开浏览器访问系统
- 自动创建.env配置文件

【兼容性】
支持操作系统：Windows、Linux、Mac
Python版本：3.10及以上
============================================================
"""

import os
import sys
import subprocess
import importlib
import webbrowser
import time
from pathlib import Path

# 基础配置
BASE_DIR = Path(__file__).resolve().parent
REQUIREMENTS_FILE = BASE_DIR / 'requirements.txt'
HOST = '127.0.0.1'
PORT = 8006


def print_banner():
    """
    打印系统启动Banner
    
    显示信息：
    - 系统名称
    - 版本号
    """
    banner = """
================================================================
   Sensitive Public Opinion Data Encryption & API Security
   Version 3.0.0
================================================================
"""
    print(banner)


def check_python_version():
    """
    检查Python版本
    
    要求：Python 3.10及以上
    
    原因：
    - 新版本性能更好
    - 支持异步特性
    - 兼容最新库
    
    返回：
    True：版本满足要求
    False：版本过低，需升级
    """
    major, minor = sys.version_info[:2]
    print(f"[Check] Python version: {sys.version.split()[0]}")
    
    if major < 3 or (major == 3 and minor < 10):
        print("[Error] Python 3.10 or higher is required!")
        print("[Info] Please install Python 3.10+ and try again")
        return False
    
    print("[Check] Python version OK")
    return True


def check_pip():
    """
    检查pip工具
    
    pip作用：
    - Python包管理器
    - 安装第三方库
    - 管理依赖
    
    自动安装：
    如果pip缺失，自动安装pip（ensurepip）
    """
    print("[Check] Checking pip...")
    
    try:
        import pip
        print(f"[Check] pip available, version: {pip.__version__}")
        return True
    except ImportError:
        print("[Check] pip not available, trying to install...")
        
        try:
            # 使用ensurepip安装pip
            subprocess.check_call([sys.executable, '-m', 'ensurepip', '--default-pip'])
            print("[Check] pip installed successfully")
            return True
        except Exception as e:
            print(f"[Error] Failed to install pip: {e}")
            return False


def get_missing_packages():
    """
    检测缺失的依赖包
    
    核心依赖：
    - fastapi：Web框架
    - uvicorn：ASGI服务器
    - sqlalchemy：数据库ORM
    - aiosqlite：异步SQLite
    - bcrypt：密码哈希
    - cryptography：加密库
    - pyjwt：JWT处理
    - python-dotenv：环境变量
    - pydantic：数据验证
    - slowapi：限流库
    
    返回：
    missing：缺失包列表
    """
    missing = []
    
    # 核心依赖包映射（模块名 → 包名）
    packages = {
        'fastapi': 'fastapi',
        'uvicorn': 'uvicorn',
        'sqlalchemy': 'sqlalchemy',
        'aiosqlite': 'aiosqlite',
        'bcrypt': 'bcrypt',
        'cryptography': 'cryptography',
        'jwt': 'pyjwt',
        'dotenv': 'python-dotenv',
        'pydantic': 'pydantic',
        'slowapi': 'slowapi',
    }
    
    print("[Check] Checking dependencies...")
    
    for module, package in packages.items():
        try:
            importlib.import_module(module)
            print(f"  [OK] {package}")
        except ImportError:
            print(f"  [Missing] {package}")
            missing.append(package)
    
    return missing


def install_dependencies():
    """
    自动安装依赖包
    
    策略：
    尝试多个镜像源，依次降级
    - 阿里云镜像（速度快）
    - 中科大镜像（稳定）
    - 华科镜像（备用）
    - 官方镜像（最终兜底）
    
    原因：
    - 国内网络环境复杂
    - 单一镜像可能不可用
    - 多镜像提高成功率
    
    trusted-host：
    - 信任镜像源，避免SSL验证错误
    """
    print("\n[Install] Installing dependencies...")
    print("[Install] This may take a few minutes, please wait...\n")
    
    # 镜像源列表（优先级排序）
    mirrors = [
        'https://mirrors.aliyun.com/pypi/simple/',      # 阿里云镜像
        'https://pypi.mirrors.ustc.edu.cn/simple/',    # 中科大镜像
        'https://pypi.hustunique.com/simple/',         # 华科镜像
        'https://pypi.org/simple/'                     # 官方镜像
    ]
    
    for i, mirror in enumerate(mirrors):
        try:
            print(f"[Install] Trying mirror ({i+1}/{len(mirrors)}): {mirror}")
            
            # 构建安装命令
            cmd = [
                sys.executable, '-m', 'pip', 'install',
                '-r', str(REQUIREMENTS_FILE),
                '-i', mirror,
                '--trusted-host', mirror.split('/')[2]  # 信任镜像源
            ]
            
            # 执行安装
            result = subprocess.run(cmd, capture_output=False)
            
            if result.returncode == 0:
                print("\n[Install] Dependencies installed successfully!")
                return True
            else:
                print(f"\n[Warn] Mirror {i+1} failed, trying next...")
        except Exception as e:
            print(f"\n[Warn] Mirror {i+1} error: {e}, trying next...")
    
    print("\n[Error] Failed to install dependencies with all mirrors!")
    print("[Error] Please run manually: pip install -r requirements.txt")
    return False


def check_env_file():
    """
    检查环境配置文件
    
    .env文件作用：
    - 存储敏感配置（密钥、密码）
    - 不提交到版本控制
    - 环境隔离
    
    自动创建：
    如果.env不存在，从.env.example复制
    """
    env_file = BASE_DIR / '.env'
    env_example = BASE_DIR / '.env.example'
    
    if not env_file.exists():
        print("[Check] .env file not found, copying from .env.example...")
        
        if env_example.exists():
            import shutil
            shutil.copy(env_example, env_file)
            print("[Check] .env file created")
        else:
            print("[Warn] .env.example not found, please create .env manually")


def start_server():
    """
    启动FastAPI服务器
    
    启动信息：
    - 服务地址：http://127.0.0.1:8006
    - 前端界面：http://127.0.0.1:8006/dashboard
    - API文档：http://127.0.0.1:8006/docs
    
    自动打开浏览器：
    方便演示和测试
    
    --reload参数：
    开发模式，代码修改后自动重启
    """
    print(f"\n[Start] Starting server...")
    print(f"[Start] Server URL: http://{HOST}:{PORT}")
    print(f"[Start] Dashboard URL: http://{HOST}:{PORT}/dashboard")
    print(f"[Start] API Docs URL: http://{HOST}:{PORT}/docs")
    print("\n[Tip] Press Ctrl+C to stop the server\n")
    
    time.sleep(1)
    
    # 自动打开浏览器
    try:
        webbrowser.open(f"http://{HOST}:{PORT}/dashboard")
    except Exception:
        pass
    
    # 构建启动命令
    cmd = [
        sys.executable, '-m', 'uvicorn', 'main:app',
        '--host', HOST,
        '--port', str(PORT),
        '--reload'  # 开发模式：代码修改自动重启
    ]
    
    try:
        subprocess.run(cmd, cwd=str(BASE_DIR))
    except KeyboardInterrupt:
        print("\n[Stop] Server stopped")
    except Exception as e:
        print(f"\n[Error] Failed to start server: {e}")
        print("[Error] Please check if the port is in use, or change the port number")


def main():
    """
    主函数：执行完整启动流程
    
    流程：
    1. 打印Banner
    2. 检查Python版本
    3. 检查pip工具
    4. 检查环境配置文件
    5. 检测缺失依赖包
    6. 自动安装缺失依赖
    7. 启动服务器
    
    错误处理：
    - 版本不满足：提示升级
    - pip缺失：自动安装
    - 依赖缺失：自动安装
    - 安装失败：提示手动安装
    """
    os.chdir(str(BASE_DIR))
    
    print_banner()
    
    # 步骤1：检查Python版本
    if not check_python_version():
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    # 步骤2：检查pip工具
    if not check_pip():
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    # 步骤3：检查环境配置文件
    check_env_file()
    
    # 步骤4：检测缺失依赖
    missing = get_missing_packages()
    
    # 步骤5：自动安装缺失依赖
    if missing:
        print(f"\n[Check] Found {len(missing)} missing dependencies")
        print("[Install] Auto-installing missing dependencies...")
        
        if not install_dependencies():
            input("\nPress Enter to exit...")
            sys.exit(1)
    else:
        print("\n[Check] All dependencies are installed")
    
    # 步骤6：启动服务器
    start_server()


if __name__ == '__main__':
    main()