#!/bin/bash
# Helper script to install liboqs-python for REAL post-quantum cryptography
# This is OPTIONAL — experiments work with mock if liboqs unavailable
#
# Usage:
#   chmod +x install_liboqs.sh
#   ./install_liboqs.sh

set -e

echo "========================================================"
echo "  Installing liboqs-python for PQSCAAS experiments"
echo "========================================================"
echo

# Detect OS
OS="$(uname -s)"
echo "Detected OS: $OS"
echo

# Install system dependencies
if [ "$OS" = "Linux" ]; then
    echo "Installing system build tools (Linux)..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y cmake gcc g++ libssl-dev python3-dev git
    elif command -v yum &> /dev/null; then
        sudo yum install -y cmake gcc gcc-c++ openssl-devel python3-devel git
    else
        echo "Warning: Unknown Linux distro. Make sure cmake, gcc, libssl-dev, python3-dev are installed."
    fi
elif [ "$OS" = "Darwin" ]; then
    echo "Installing system build tools (macOS)..."
    if ! command -v brew &> /dev/null; then
        echo "Error: Homebrew not found. Install from https://brew.sh"
        exit 1
    fi
    brew install cmake openssl git
elif [[ "$OS" == MINGW* || "$OS" == CYGWIN* ]]; then
    echo "Windows detected. Please install:"
    echo "  - CMake (https://cmake.org/download/)"
    echo "  - Visual Studio Build Tools"
    echo "  - Git for Windows"
    echo "Then run: pip install liboqs-python"
    exit 1
fi

# Install Python package
echo
echo "Installing liboqs-python via pip..."
pip install --break-system-packages liboqs-python 2>/dev/null || \
pip install liboqs-python

# Verify
echo
echo "Verifying installation..."
python3 -c "
import oqs
print(f'✓ liboqs-python version: {oqs.oqs_python_version()}')
print(f'✓ liboqs version: {oqs.oqs_version()}')
kems = oqs.get_enabled_kem_mechanisms()
sigs = oqs.get_enabled_sig_mechanisms()
if 'ML-KEM-768' in kems:
    print('✓ ML-KEM-768 supported')
else:
    print('✗ ML-KEM-768 NOT found — available KEMs:', [k for k in kems if 'KEM' in k][:5])
if 'ML-DSA-65' in sigs:
    print('✓ ML-DSA-65 supported')
else:
    print('✗ ML-DSA-65 NOT found — available sigs:', [s for s in sigs if 'DSA' in s][:5])
"

echo
echo "========================================================"
echo "  Installation complete!"
echo "========================================================"
echo "Now you can run the experiments with REAL PQ crypto:"
echo "  python3 run_all_experiments.py"
