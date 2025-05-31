$ErrorActionPreference = "Stop"

$venvDir = ".venv"

# Create virtual environment if it doesn't exist
if (-not (Test-Path $venvDir)) {
    Write-Host "Creating virtual environment..."
    python -m venv $venvDir
}

# Activate virtual environment
$activateScript = Join-Path $venvDir "Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    Write-Error "Cannot find activate script at $activateScript"
    exit 1
}
Write-Host "Activating virtual environment..."
& $activateScript

python.exe -m pip install --upgrade pip

# Ensure pip and maturin are installed
Write-Host "Installing/Upgrading pip and maturin..."
pip install --upgrade pip maturin

# Build and install with maturin
Write-Host "Building and installing with maturin..."
maturin develop --release
