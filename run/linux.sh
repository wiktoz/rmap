#!/bin/bash

set -e

VENV_DIR=".venv"

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "🧪 Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

python.exe -m pip install --upgrade pip

# Ensure pip and maturin are installed
echo "⬆️  Installing/Upgrading pip and maturin..."
pip install --upgrade pip maturin

# Build and install the Rust extension
echo "🔧 Building and installing with maturin..."
maturin develop --release

# Test import
echo "✅ Testing import..."
python -c "import rmap; print('✅ rmap import successful.')"