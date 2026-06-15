//go:build windows
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

type WindowsSandbox struct {
    id string
}

type WindowsFactory struct{}

func (f *WindowsFactory) Create(ctx context.Context) (OSProcessSandbox, error) {
    id := fmt.Sprintf("sb-win-%d", time.Now().UnixNano())
    return &WindowsSandbox{id: id}, nil
}

func (s *WindowsSandbox) ID() string {
    return s.id
}

func (s *WindowsSandbox) Execute(ctx context.Context, req ExecRequest) (*ExecResult, error) {
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
        codePath += ".bat"
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
        cmdArgs = []string{"python", codePath}
    } else {
        cmdArgs = []string{"cmd.exe", "/C", codePath}
    }

    cmd := exec.CommandContext(execCtx, cmdArgs[0], cmdArgs[1:]...)
    
    // For a production Windows environment, we would use:
    // cmd.SysProcAttr = &syscall.SysProcAttr{
    //     CreationFlags: syscall.CREATE_SUSPENDED,
    // }
    // Then assign the process handle to a heavily restricted Job Object
    // before resuming the thread.

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

func (s *WindowsSandbox) Destroy(ctx context.Context) error {
    return nil
}

func NewOSFactory() SandboxFactory {
	return &WindowsFactory{}
}
