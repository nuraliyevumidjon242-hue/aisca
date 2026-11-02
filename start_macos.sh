#!/usr/bin/env bash
set -e

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker Desktop/CLI is required. Please install Docker and try again."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: Python 3.11+ is required. Please install Python 3.11+ and try again."
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
fi

echo "[AISCA] Starting application with Docker Compose..."
if command -v docker-compose >/dev/null 2>&1; then
  docker-compose up --build
else
  docker compose up --build
fi
