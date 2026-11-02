#!/usr/bin/env bash
set -euo pipefail

# Quick helper to create venv, install deps and run the backend locally
# Usage: bash run_local.sh

ROOT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT_DIR"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create a local admin if environment variables provided
if [ -n "${AISCA_ADMIN_USER:-}" ] && [ -n "${AISCA_ADMIN_PASS:-}" ]; then
  python3 scripts/create_admin.py --username "$AISCA_ADMIN_USER" --password "$AISCA_ADMIN_PASS" --db scans.db || true
fi

# Run uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000
