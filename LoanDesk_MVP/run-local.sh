#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -f .env ]; then cp .env.example .env; echo "Created .env from .env.example"; fi
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
set -a; source .env; set +a
exec python -m uvicorn backend.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
