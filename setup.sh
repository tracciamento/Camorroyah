#!/usr/bin/env bash
set -e
if command -v termux-info >/dev/null 2>&1 || [ -n "$TERMUX_VERSION" ]; then
    echo "[*] Termux detected"
    pkg update -y
    pkg install -y python git nano
else
    echo "[*] Linux detected"
    sudo apt update
    sudo apt install -y python3 git
fi
echo "[+] WebForge جاهز — شغّل: python3 webforge.py --list"
