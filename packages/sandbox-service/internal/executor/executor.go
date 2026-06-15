package executor

import (
    "context"
    "fmt"

    "wh-agent/sandbox-service/internal/vm"
)

type Engine struct {
    factory vm.SandboxFactory
    sem     chan struct{}
}

func NewEngine(maxConcurrent int, factory vm.SandboxFactory) *Engine {
    return &Engine{
        factory: factory,
        sem:     make(chan struct{}, maxConcurrent),
    }
}

func (e *Engine) Execute(ctx context.Context, req vm.ExecRequest) (*vm.ExecResult, error) {
    // Acquire semaphore to enforce concurrency limits
    select {
    case e.sem <- struct{}{}:
    case <-ctx.Done():
        return nil, ctx.Err()
    }
    defer func() { <-e.sem }()

    // Because OS-native sandboxes have sub-millisecond cold starts,
    // we instantiate a fresh, isolated process wrapper for every request.
    sandbox, err := e.factory.Create(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to create sandbox process: %w", err)
    }
    
    // Ensure cleanup of any temp resources
    defer sandbox.Destroy(context.Background())

    // Execute synchronously
    return sandbox.Execute(ctx, req)
}
