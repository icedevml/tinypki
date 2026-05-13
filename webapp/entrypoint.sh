#!/bin/sh
set -e

echo "[!] Run alembic upgrade head"
alembic upgrade head

echo "[!] Run app"
python3 -m main
