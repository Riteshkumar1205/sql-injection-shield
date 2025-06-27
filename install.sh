#!/bin/bash
# Linux SQLi Shield Installer

set -e

# Check dependencies
if ! command -v java &> /dev/null; then
    echo "Installing OpenJDK..."
    sudo apt-get update && sudo apt-get install -y openjdk-11-jdk
fi

if ! command -v pip3 &> /dev/null; then
    echo "Installing Python pip..."
    sudo apt-get install -y python3-pip
fi

# Create config directory
CONFIG_DIR="$HOME/.sqli_shield"
mkdir -p "$CONFIG_DIR/models"

# Install Python dependencies
pip3 install tensorflow transformers scikit-learn

# Download AI models
echo "Downloading AI models..."
wget -O "$CONFIG_DIR/models/cnn_model.h5" https://example.com/models/cnn_model.h5
wget -O "$CONFIG_DIR/models/rf_model.pkl" https://example.com/models/rf_model.pkl

# Create desktop launcher
cat > ~/.local/share/applications/sqli-shield.desktop <<EOL
[Desktop Entry]
Name=SQLi Shield
Comment=Burp Extension for SQL Injection Detection
Exec=java -jar -Xmx2g /path/to/burpsuite_pro.jar --python-script=$PWD/burp_integration.py
Icon=security-high
Terminal=false
Type=Application
Categories=Security;
EOL

chmod +x ~/.local/share/applications/sqli-shield.desktop

echo "✅ Installation complete! Launch from Applications > Security"
