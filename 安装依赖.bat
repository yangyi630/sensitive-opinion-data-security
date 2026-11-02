@echo off
chcp 65001 >nul
title 一键安装依赖

cd /d "%~dp0"

echo.
echo ===========================================
echo   一键安装依赖包
echo ===========================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [错误] 未检测到Python！
    echo [提示] 请先安装Python 3.10或更高版本
    pause
    exit /b 1
)

echo [检测] %python%
echo.
echo [安装] 正在安装依赖包...
echo [安装] 使用清华镜像源加速下载
echo [安装] 这可能需要几分钟时间...
echo.

python -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

if %errorlevel% equ 0 (
    echo.
    echo [成功] 依赖安装完成！
    echo [提示] 现在可以双击 "启动系统.bat" 运行程序
) else (
    echo.
    echo [警告] 清华镜像源安装失败，尝试官方源...
    echo.
    python -m pip install -r requirements.txt
    if %errorlevel% equ 0 (
        echo.
        echo [成功] 依赖安装完成！
    ) else (
        echo.
        echo [错误] 依赖安装失败！
        echo [提示] 请检查网络连接后重试
    )
)

echo.
pause
