package vm

import (
    "context"
)

type ExecRequest struct {
    Code      string
    Language  string
    TimeoutMs int
    Env       map[string]string
    MaxMemMB  int
    MaxCPUPct float64
}

type ExecResult struct {
    Stdout           string
    Stderr           string
    ExitCode         int
    ExecutionMs      int64
    SandboxID        string
    Killed           bool
}

type OSProcessSandbox interface {
    ID() string
    Execute(ctx context.Context, req ExecRequest) (*ExecResult, error)
    Destroy(ctx context.Context) error
}

type SandboxFactory interface {
    Create(ctx context.Context) (OSProcessSandbox, error)
}
