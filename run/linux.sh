#!/bin/bash

set -e

VENV_DIR=".venv"

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
chmod +x "$VENV_DIR/bin/activate"
source "$VENV_DIR/bin/activate"

# Detect conflicting Python envs
if [ -n "$VIRTUAL_ENV" ] && [ -n "$CONDA_PREFIX" ]; then
    echo "Both VIRTUAL_ENV and CONDA_PREFIX are set."
    echo "Deactivating conda environment to avoid conflicts..."
    conda deactivate || {
        echo "Warning: Failed to deactivate conda environment."
        echo "Please manually deactivate it and re-run this script."
        exit 1
    }
fi

# Upgrade pip to the latest version
python -m pip install --upgrade pip

# Ensure pip and maturin are installed
echo "Installing/Upgrading pip and maturin..."
pip install --upgrade pip maturin

# Build and install the Rust lib
echo "Building and installing with maturin..."
maturin develop --release

# Test import
echo "Testing import..."
python -c "import rmap; print('rmap import successful.')"