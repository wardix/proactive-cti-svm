#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================================================="
echo "  Proactive Cyber Security Defense Model (CTI-SVM)"
echo "  PhD Thesis Implementation - Syurahbil (UUM, 2024)"
echo "=================================================================="

cleanup() {
  echo ""
  echo "[INFO] Menghentikan seluruh layanan..."
  [[ -n "${ML_PID:-}" ]] && kill "$ML_PID" 2>/dev/null || true
  [[ -n "${PHP_PID:-}" ]] && kill "$PHP_PID" 2>/dev/null || true
  [[ -n "${VITE_PID:-}" ]] && kill "$VITE_PID" 2>/dev/null || true
  exit 0
}
trap cleanup SIGINT SIGTERM

echo "[1/3] Menjalankan Python FastAPI SVM Service di http://127.0.0.1:8001 ..."
(
  cd "$ROOT_DIR/ml-service"
  "$ROOT_DIR/ml-service/.venv/bin/uvicorn" app.main:app --host 127.0.0.1 --port 8001
) &
ML_PID=$!

sleep 2

echo "[2/3] Menjalankan Laravel PHP Backend API di http://127.0.0.1:8000 ..."
(
  cd "$ROOT_DIR/backend"
  php -S 127.0.0.1:8000 -t public public/index.php
) &
PHP_PID=$!

sleep 1

echo "[3/3] Menjalankan React.js Vite Dashboard di http://127.0.0.1:5173 ..."
(
  cd "$ROOT_DIR/frontend"
  npm run dev -- --host 127.0.0.1 --port 5173
) &
VITE_PID=$!

echo ""
echo "=================================================================="
echo "  Semua layanan aktif!"
echo "  - Dashboard UI (React.js) : http://127.0.0.1:5173"
echo "  - Backend API (PHP)       : http://127.0.0.1:8000/api/overview"
echo "  - SVM ML Service (Python) : http://127.0.0.1:8001/health"
echo "  Tekan Ctrl+C untuk menghentikan semua layanan."
echo "=================================================================="

wait
