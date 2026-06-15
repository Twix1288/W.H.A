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

type LinuxSandbox struct {
    id string
}

type LinuxFactory struct{}

func (f *LinuxFactory) Create(ctx context.Context) (OSProcessSandbox, error) {
    id := fmt.Sprintf("sb-linux-%d", time.Now().UnixNano())
    return &LinuxSandbox{id: id}, nil
}

func (s *LinuxSandbox) ID() string {
    return s.id
}

func (s *LinuxSandbox) Execute(ctx context.Context, req ExecRequest) (*ExecResult, error) {
    start := time.Now()

    tmpDir, err := os.MkdirTemp("", "sandbox-*")
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

    var cmdArgs []string
    if req.Language == "python" {
        cmdArgs = []string{"python3", codePath}
    } else {
        cmdArgs = []string{"bash", codePath}
    }

    cmd := exec.CommandContext(execCtx, cmdArgs[0], cmdArgs[1:]...)
    
    // For a production Linux environment, we would use:
    // cmd.SysProcAttr = &syscall.SysProcAttr{
    //     Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
    // }
    // Followed by applying Landlock rules.
    // This is a stub for the OS-native architecture.

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

func (s *LinuxSandbox) Destroy(ctx context.Context) error {
    return nil
}

func NewOSFactory() SandboxFactory {
	return &LinuxFactory{}
}
