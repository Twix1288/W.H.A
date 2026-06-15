#!/usr/bin/env bash
set -e

echo "🛡️  W.H.Agent Developer Bootstrap 🛡️"
echo "========================================"

# Check for required tools
command -v pnpm >/dev/null 2>&1 || { echo "Error: pnpm is required but not installed. Aborting." >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "Error: go is required but not installed. Aborting." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Warning: docker is recommended for local infrastructure." >&2; }

echo "[1/4] Installing Node dependencies..."
pnpm install

echo "[2/4] Downloading Go modules..."
cd packages/ebpf-agent && go mod tidy && cd ../..
# cd packages/posture-service && go mod tidy && cd ../..

echo "[3/4] Checking eBPF tooling (clang/llvm)..."
if command -v clang >/dev/null 2>&1; then
    echo "    clang found. Native eBPF compilation supported."
else
    echo "    clang not found. You will need to use Docker to compile the eBPF C code."
fi

echo "[4/4] Setup complete!"
echo ""
echo "Run 'make build' to compile all services."
echo "Run 'make dev' to start local infrastructure (Kafka, Postgres)."
