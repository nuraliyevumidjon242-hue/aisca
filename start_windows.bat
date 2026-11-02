@echo off
setlocal

echo [AISCA] Checking Docker and Python...
where docker >nul 2>nul
if errorlevel 1 (
  echo ERROR: Docker Desktop is not installed or not in PATH.
  echo Please install Docker Desktop and restart this terminal.
  exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python 3.11+ is required.
  echo Install Python from https://www.python.org/downloads/windows/
  exit /b 1
)

if not exist .env (
  copy .env.example .env >nul
)

echo [AISCA] Starting services with Docker Compose...
where docker-compose >nul 2>nul
if not errorlevel 1 (
  docker-compose up --build
) else (
  docker compose up --build
)
