#!/bin/sh
set -e

echo "[!] Run alembic upgrade head"
alembic upgrade head

echo "[!] Run app"
fastapi run main.py --proxy-headers --port 8080
