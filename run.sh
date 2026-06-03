#!/usr/bin/env bash
# Lance l'application Email Manager en local (Linux / macOS).
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "[Email Manager] Création de l'environnement Python…"
  python3 -m venv .venv
  ./.venv/bin/python -m pip install --upgrade pip >/dev/null
  echo "[Email Manager] Installation des dépendances…"
  ./.venv/bin/python -m pip install -r requirements.txt
fi

echo
echo "============================================================"
echo "  Email Manager → http://127.0.0.1:8000   (Ctrl+C pour arrêter)"
echo "============================================================"
echo

cd backend
../.venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
