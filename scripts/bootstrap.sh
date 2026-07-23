#!/usr/bin/env bash
set -e

echo "🛡️  W.H.Agent Developer Bootstrap"
echo "===================================="

# Required toolchain
command -v pnpm >/dev/null 2>&1 || { echo "Error: pnpm is required but not installed. Aborting." >&2; exit 1; }
command -v go   >/dev/null 2>&1 || { echo "Error: go (1.26+) is required but not installed. Aborting." >&2; exit 1; }

echo "[1/3] Installing Node dependencies (pnpm install)..."
pnpm install

echo "[2/3] Fetching Go modules for the sandbox service..."
( cd packages/sandbox-service && go mod download )

echo "[3/3] Building the sandbox binary into packages/cli/bin ..."
make build-sandbox

echo ""
echo "Setup complete."
echo "  • Build everything:     make build"
echo "  • Run all tests:        make test"
echo "  • Run the CLI from src:  pnpm --filter wh-agent-cli dev -- scan --help"
