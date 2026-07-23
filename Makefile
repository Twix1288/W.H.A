.PHONY: all build build-sandbox build-cli test test-ts test-go lint type-check bootstrap dev clean

# ── W.H.Agent build orchestration ─────────────────────────────────────────────
# The product is two components that ship together:
#   • packages/cli             — the TypeScript CLI (published as `wh-agent-cli`),
#                                bundled with tsup.
#   • packages/sandbox-service — the Go OS-sandbox binary (`wh-sandbox`) that the
#                                CLI spawns for `wh-agent run`.
#
# The compiled sandbox binary is written to packages/cli/bin/wh-sandbox, which the
# CLI resolves at runtime (see packages/cli/src/commands/run.ts) and npm ships via
# the CLI package's "files" list. Real isolation is macOS-only today; on Linux and
# Windows the binary intentionally fails closed.
# ──────────────────────────────────────────────────────────────────────────────

SANDBOX_DIR := packages/sandbox-service
SANDBOX_OUT := $(CURDIR)/packages/cli/bin/wh-sandbox

all: build

## build: compile the Go sandbox binary, then build the TypeScript packages.
build: build-sandbox build-cli
	@echo "==> Build complete."

## build-sandbox: compile wh-sandbox (Go) into the CLI's bin/ for the host platform.
build-sandbox:
	@echo "==> Building wh-sandbox (Go) -> packages/cli/bin/wh-sandbox"
	@mkdir -p "$(dir $(SANDBOX_OUT))"
	@cd $(SANDBOX_DIR) && go build -o "$(SANDBOX_OUT)" ./cmd/wh-sandbox

## build-cli: install deps and build the TypeScript packages via turbo.
build-cli:
	@echo "==> Building TypeScript packages"
	@pnpm install
	@pnpm turbo build

## test: run every test suite (TypeScript + Go), mirroring CI.
test: test-ts test-go

test-ts:
	@pnpm turbo test

test-go:
	@cd $(SANDBOX_DIR) && go vet ./... && go test ./...

lint:
	@pnpm turbo lint

type-check:
	@pnpm turbo type-check

## bootstrap: check the toolchain, install deps, and build the sandbox binary.
bootstrap:
	@bash scripts/bootstrap.sh

## dev: run the CLI directly from TypeScript source (no build step).
##      Build the sandbox first if you want `wh-agent run` to work locally.
dev:
	@echo "==> Run the CLI from source:  pnpm --filter wh-agent-cli dev -- <command>"
	@echo "    For 'run' support first:  make build-sandbox"

## clean: remove build artifacts (including the compiled sandbox binary).
clean:
	@echo "==> Cleaning build artifacts"
	@rm -f "$(SANDBOX_OUT)"
	@pnpm turbo clean || true
	@find . -name "node_modules" -type d -prune -exec rm -rf '{}' + 2>/dev/null || true
