//go:build darwin
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

type DarwinSandbox struct {
    id string
}

type DarwinFactory struct{}

func (f *DarwinFactory) Create(ctx context.Context) (OSProcessSandbox, error) {
    id := fmt.Sprintf("sb-mac-%d", time.Now().UnixNano())
    return &DarwinSandbox{id: id}, nil
}

func (s *DarwinSandbox) ID() string {
    return s.id
}

func (s *DarwinSandbox) Execute(ctx context.Context, req ExecRequest) (*ExecResult, error) {
    start := time.Now()

    // 1. Create a secure temporary directory for this execution
    tmpDir, err := os.MkdirTemp("", "sandbox-*")
    if err != nil {
        return nil, fmt.Errorf("failed to create temp dir: %w", err)
    }
    defer os.RemoveAll(tmpDir)

    // 2. Write the code to a file
    codePath := filepath.Join(tmpDir, "script")
    if req.Language == "python" {
        codePath += ".py"
    } else {
        codePath += ".sh"
    }

    if err := os.WriteFile(codePath, []byte(req.Code), 0755); err != nil {
        return nil, fmt.Errorf("failed to write code: %w", err)
    }

    // 3. Generate Seatbelt profile
    // This profile denies everything by default, allows reading everywhere (for libraries),
    // but strictly denies network egress and restricts writing to the temp dir only.
    profile := fmt.Sprintf(`(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow file-read*)
(allow file-write* (subpath "%s"))
(deny network*)
`, tmpDir)

    profilePath := filepath.Join(tmpDir, "profile.sb")
    if err := os.WriteFile(profilePath, []byte(profile), 0644); err != nil {
        return nil, fmt.Errorf("failed to write profile: %w", err)
    }

    // 4. Construct execution command
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

    // Wrap with sandbox-exec
    args := append([]string{"-f", profilePath}, cmdArgs...)
    cmd := exec.CommandContext(execCtx, "sandbox-exec", args...)
    
    // Pass explicitly allowed environment variables
    for k, v := range req.Env {
        cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
    }
    // Need basic env for python to find stdlib sometimes, but let's see if it works without

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

func (s *DarwinSandbox) Destroy(ctx context.Context) error {
    // Process exits instantly, no state to tear down
    return nil
}

func NewOSFactory() SandboxFactory {
	return &DarwinFactory{}
}
