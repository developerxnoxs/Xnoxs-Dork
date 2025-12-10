#!/bin/bash

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║            xnoxs-dork Installer                                ║"
echo "║     SQL Injection & XSS Vulnerability Scanner                  ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

if command -v pkg &> /dev/null; then
    echo "[*] Termux detected, installing dependencies..."
    pkg update -y
    pkg install python -y
    pip install colorama requests beautifulsoup4
elif command -v apt &> /dev/null; then
    echo "[*] Debian/Ubuntu detected..."
    pip3 install colorama requests beautifulsoup4
elif command -v yum &> /dev/null; then
    echo "[*] CentOS/RHEL detected..."
    pip3 install colorama requests beautifulsoup4
elif command -v pacman &> /dev/null; then
    echo "[*] Arch Linux detected..."
    pip install colorama requests beautifulsoup4
else
    echo "[*] Installing Python dependencies..."
    pip install colorama requests beautifulsoup4 2>/dev/null || pip3 install colorama requests beautifulsoup4
fi

echo ""
echo "[*] Installing xnoxs-dork..."

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

cp xnoxs_dork.py "$INSTALL_DIR/"
cp xnoxs-dork "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/xnoxs-dork"

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "[!] Add this to your ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "[*] Or run: source ~/.bashrc"
fi

echo ""
echo "[+] Installation complete!"
echo "[*] Run 'xnoxs-dork' to start the tool"
echo ""
