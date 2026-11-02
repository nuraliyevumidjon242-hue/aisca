@echo off
title AISCA - Docker Launch (Windows)
cls
echo ====================================================
echo    AISCA - Docker Launch (Windows)
echo ====================================================
echo.

docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [XATO] Docker topilmadi yoki ishga tushmagan.
    echo Iltimos, Docker Desktop dasturini ishga tushiring.
    pause
    exit /b 1
)

if exist .env.example (
    if not exist .env (
        echo [INFO] .env fayli yaratilmoqda...
        copy .env.example .env >nul
    )
)

echo [INFO] Frontend manzili: http://localhost:3000
echo [INFO] Backend API manzili: http://localhost:8000
echo [INFO] Docker konteynerlari yig'ilmoqda va ishga tushirilmoqda...
echo ----------------------------------------------------

docker compose up --build
if %errorlevel% neq 0 (
    docker-compose up --build
)

pause
