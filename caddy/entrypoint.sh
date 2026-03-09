#!/bin/bash

set -e

echo "[!] Executing entrypoint.py"
/usr/bin/python3 -u /entrypoint.py

echo "[!] Launching Caddy..."
exec "${@}"

