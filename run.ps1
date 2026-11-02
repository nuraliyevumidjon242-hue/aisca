Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "🚀 AISCA - Docker Launch (Windows PowerShell)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "❌ XATO: Docker topilmadi yoki ishga tushmagan." -ForegroundColor Red
    Write-Host "Iltimos, Docker Desktop dasturini ishga tushiring." -ForegroundColor Yellow
    Read-Host "Davom etish uchun Enter bosing..."
    exit 1
}

if ((Test-Path .env.example) -and (-not (Test-Path .env))) {
    Write-Host "📝 .env fayli yaratilmoqda..." -ForegroundColor Yellow
    Copy-Item .env.example .env
}

Write-Host "📍 Frontend manzili: http://localhost:3000" -ForegroundColor Yellow
Write-Host "📍 Backend API manzili: http://localhost:8000" -ForegroundColor Yellow
Write-Host "📦 Docker konteynerlari yig'ilmoqda va ishga tushirilmoqda..." -ForegroundColor Green
Write-Host "----------------------------------------------------"

try {
    docker compose up --build
} catch {
    docker-compose up --build
}
