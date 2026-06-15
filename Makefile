.PHONY: all build build-ebpf build-go build-ts test clean dev

# Detect OS and architecture
OS := $(shell uname -s)
ARCH := $(shell uname -m)

all: bootstrap build

bootstrap:
	@echo "==> Bootstrapping W.H.Agent Monorepo..."
	@bash scripts/bootstrap.sh

build: build-ebpf build-go build-ts
	@echo "==> Build complete."

build-ebpf:
	@echo "==> Compiling eBPF C programs..."
	@if [ "$(OS)" = "Linux" ]; then \
		cd packages/ebpf-agent && go generate ./...; \
	else \
		echo "    Skipping eBPF compilation (Linux required). Use 'make build-ebpf-docker' to compile via Docker on macOS/Windows."; \
	fi

build-go:
	@echo "==> Building Go microservices..."
	@cd packages/ebpf-agent && go build -o bin/wh-agent-ebpf src/loader/main.go src/loader/loader_*.go
	@cd packages/posture-service && go build -o bin/posture-service src/main.go

build-ts:
	@echo "==> Building TypeScript packages..."
	@pnpm install
	@pnpm run build

dev:
	@echo "==> Starting local development environment..."
	@docker-compose up -d postgres kafka redis
	@echo "    Infrastructure running. Use 'pnpm run dev' to start Node services."

test:
	@echo "==> Running test suites..."
	@cd packages/ebpf-agent && go test ./...
	@cd packages/posture-service && go test ./...
	@pnpm run test

clean:
	@echo "==> Cleaning build artifacts..."
	@rm -rf packages/ebpf-agent/bin/
	@rm -rf packages/posture-service/bin/
	@pnpm run clean
	@find . -name "node_modules" -type d -prune -exec rm -rf '{}' +
