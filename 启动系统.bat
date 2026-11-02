@echo off
chcp 65001 >nul
title 涉敏舆情数据加密传输与API安全防护系统

cd /d "%~dp0"

echo.
echo ===========================================
echo   涉敏舆情数据加密传输与API安全防护系统
echo   Version 3.0.0
echo ===========================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [错误] 未检测到Python！
    echo [提示] 请先安装Python 3.10或更高版本
    echo [提示] 下载地址: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

for /f "delims=" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo [检测] %PYVER%

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if %errorlevel% neq 0 (
    echo [错误] Python版本过低，需要Python 3.10或更高版本！
    echo.
    pause
    exit /b 1
)

echo [检测] Python版本符合要求
echo.
echo [启动] 正在启动系统...
echo [提示] 启动后将自动打开浏览器
echo [提示] 按 Ctrl+C 可停止服务器
echo.

python app.py

if %errorlevel% neq 0 (
    echo.
    echo [错误] 启动失败！
    echo [提示] 请检查是否安装了Python及相关依赖
)

echo.
pause
