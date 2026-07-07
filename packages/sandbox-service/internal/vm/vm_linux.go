//go:build linux
package vm

import (
    "bytes"
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "time"
)

type LandlockSandbox struct {
    id string
}

type LandlockFactory struct{}

func (f *LandlockFactory) Create(ctx context.Context) (OSProcessSandbox, error) {
    id := fmt.Sprintf("sb-landlock-%d", time.Now().UnixNano())
    return &LandlockSandbox{id: id}, nil
}

func (s *LandlockSandbox) ID() string {
    return s.id
}

// Execute FAILS CLOSED.
//
// The Landlock + namespace enforcement for this backend is not implemented yet.
// Previously this method ran the untrusted payload as an ordinary child process
// with NO isolation whatsoever — full host access — which is strictly worse than
// not running it: it hands out a false sense of containment. Until real
// enforcement lands we refuse to execute.
//
// Real implementation outline:
//   - apply a Landlock ruleset (e.g. github.com/landlock-lsm/go-landlock)
//     restricting the process to the scratch directory only;
//   - drop into user + network + mount namespaces via
//     cmd.SysProcAttr = &syscall.SysProcAttr{
//         Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
//     };
//   - then exec the interpreter.
func (s *LandlockSandbox) Execute(ctx context.Context, req ExecRequest) (*ExecResult, error) {
    return nil, fmt.Errorf(
        "landlock sandbox backend is not implemented: refusing to execute untrusted code without isolation " +
            "(set WH_SANDBOX_BACKEND=gvisor with gVisor/runsc installed, or use the macOS backend)")
}

func (s *LandlockSandbox) Destroy(ctx context.Context) error {
    return nil
}

// --- gVisor Implementation ---

type GvisorSandbox struct {
    id string
}

type GvisorFactory struct{}

func (f *GvisorFactory) Create(ctx context.Context) (OSProcessSandbox, error) {
    id := fmt.Sprintf("sb-gvisor-%d", time.Now().UnixNano())
    return &GvisorSandbox{id: id}, nil
}

func (s *GvisorSandbox) ID() string {
    return s.id
}

func (s *GvisorSandbox) Execute(ctx context.Context, req ExecRequest) (*ExecResult, error) {
    start := time.Now()

    // Fail closed with a clear message if the gVisor runtime is unavailable,
    // rather than surfacing a cryptic "executable file not found" from exec.
    if _, err := exec.LookPath("runsc"); err != nil {
        return nil, fmt.Errorf("gvisor backend selected but `runsc` was not found on PATH; install gVisor or choose another backend: %w", err)
    }

    tmpDir, err := os.MkdirTemp("", "gvisor-*")
    if err != nil {
        return nil, fmt.Errorf("failed to create temp dir: %w", err)
    }
    defer os.RemoveAll(tmpDir)

    codePath := filepath.Join(tmpDir, "script")
    if req.Language == "python" {
        codePath += ".py"
    } else {
        codePath += ".sh"
    }

    if err := os.WriteFile(codePath, []byte(req.Code), 0755); err != nil {
        return nil, fmt.Errorf("failed to write code: %w", err)
    }

    timeout := time.Duration(req.TimeoutMs) * time.Millisecond
    if timeout == 0 {
        timeout = 5 * time.Second
    }

    execCtx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()

    // NOTE: `runsc do` runs under gVisor's syscall interception but, by default,
    // maps the host filesystem into the sandbox — so it restricts syscalls but
    // does NOT by itself hide host file *contents*. A hardened deployment should
    // run the payload from a minimal OCI bundle with an isolated rootfs (only
    // the scratch dir bind-mounted) and `--network=none`. Tracked as follow-up.
    var cmdArgs []string
    if req.Language == "python" {
        cmdArgs = []string{"runsc", "do", "python3", codePath}
    } else {
        cmdArgs = []string{"runsc", "do", "bash", codePath}
    }

    cmd := exec.CommandContext(execCtx, cmdArgs[0], cmdArgs[1:]...)

    for k, v := range req.Env {
        cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
    }

    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    err = cmd.Run()

    exitCode := 0
    killed := false
    if err != nil {
        if exitError, ok := err.(*exec.ExitError); ok {
            exitCode = exitError.ExitCode()
        } else {
            exitCode = -1
        }
        if execCtx.Err() == context.DeadlineExceeded {
            killed = true
        }
    }

    return &ExecResult{
        Stdout:      stdout.String(),
        Stderr:      stderr.String(),
        ExitCode:    exitCode,
        ExecutionMs: time.Since(start).Milliseconds(),
        SandboxID:   s.id,
        Killed:      killed,
    }, nil
}

func (s *GvisorSandbox) Destroy(ctx context.Context) error {
    return nil
}

// --- Factory Selection ---
//
// The default (no WH_SANDBOX_BACKEND, or "landlock") now fails closed until the
// Landlock backend is implemented — a secure default is to refuse to run
// untrusted code rather than run it with no isolation.
func NewOSFactory() SandboxFactory {
    backend := os.Getenv("WH_SANDBOX_BACKEND")
    if backend == "gvisor" {
        return &GvisorFactory{}
    }
    return &LandlockFactory{}
}
