#!/usr/bin/env bash
set -e

echo "===================================================="
echo "🚀 AISCA - Docker Launch (macOS / Linux)"
echo "===================================================="

if ! command -v docker >/dev/null 2>&1; then
  echo "❌ XATO: Docker topilmadi. Iltimos Docker Desktop-ni ishga tushiring."
  exit 1
fi

if [ -f .env.example ] && [ ! -f .env ]; then
  echo "📝 .env fayli yaratilmoqda..."
  cp .env.example .env
fi

echo "📍 Frontend manzili: http://localhost:3000"
echo "📍 Backend API manzili: http://localhost:8000"
echo "📦 Docker konteynerlari yig'ilmoqda va ishga tushirilmoqda..."
echo "----------------------------------------------------"

if command -v docker-compose >/dev/null 2>&1; then
  docker-compose up --build
else
  docker compose up --build
fi
