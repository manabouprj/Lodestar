#!/usr/bin/env bash
# LODESTAR - Linux/macOS setup and demo.  Usage: ./scripts/setup.sh [--serve]
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
. .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements-dev.txt
python -m pytest -q
python -m lodestar demo
[ -f .env ] || cp .env.example .env
if [[ "${1:-}" == "--serve" ]]; then python -m lodestar serve; fi
