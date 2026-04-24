#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="pqscaas-sgx"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not installed or not on PATH." >&2
  exit 1
fi

cd "$SCRIPT_DIR"

echo "Building ${IMAGE_NAME}..."
if docker buildx version >/dev/null 2>&1; then
  docker buildx build --platform linux/amd64 --load -t "$IMAGE_NAME" .
else
  docker build -t "$IMAGE_NAME" .
fi

echo "Running SGX workflow inside ${IMAGE_NAME}..."
docker run --platform linux/amd64 --rm \
  -v "$SCRIPT_DIR":/pqscaas_sgx \
  "$IMAGE_NAME" bash -lc 'source /sgxsdk/environment && make SGX_MODE=SIM && ./pqscaas_experiments && python3 plot_all.py'