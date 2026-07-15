package vm

import (
    "context"
    "fmt"
)

type ExecRequest struct {
    Code      string
    Language  string
    TimeoutMs int
    Env       map[string]string
    MaxMemMB  int
    MaxCPUPct float64
}

// ValidateLanguage rejects any language the sandbox does not explicitly support.
//
// Without this, every backend's `if req.Language == "python" { ... } else { ... }`
// dispatch treats ANY other value — a typo, an empty string, or attacker-chosen
// input — as a shell script and runs it through bash/cmd.exe. That is a silent
// widening of what gets executed, so we fail closed at ingestion instead. An
// empty string is allowed and is treated as bash by the backends (preserving the
// prior default), but unknown values are refused.
func ValidateLanguage(lang string) error {
    switch lang {
    case "python", "bash", "":
        return nil
    default:
        return fmt.Errorf("unsupported language %q (allowed: python, bash)", lang)
    }
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
