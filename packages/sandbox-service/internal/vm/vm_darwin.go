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

    // 3. Generate a default-DENY Seatbelt profile (allow-list model).
    //
    // Nothing is readable unless explicitly allowed, so the user's home
    // (~/.ssh, ~/.aws, ~/.config, Documents), /Volumes, /tmp, and every other
    // host location are denied by *omission* — not by a fragile deny-list.
    //
    // We build on Apple's own base profile `bsd.sb` (which imports system.sb ->
    // dyld-support.sb). That base is what correctly grants the reads/maps a
    // process needs to launch on THIS macOS version: the dyld shared cache,
    // /System, /usr/lib, /usr/share, /dev, and the mach services for name
    // resolution. Reproducing that by hand is why a naive allow-list aborts
    // every binary at startup — on macOS, mapping a dylib needs the separate
    // `file-map-executable` permission, not just `file-read*`. Relying on the
    // platform base also means we track OS changes for free, and if the base
    // profile is ever missing the sandbox fails *closed* (nothing executes).
    //
    // Resolve symlinks so subpath matching runs against the canonical path
    // (on macOS $TMPDIR is /var/folders -> /private/var/folders).
    realTmp, symErr := filepath.EvalSymlinks(tmpDir)
    if symErr != nil {
        realTmp = tmpDir
    }

    profile := fmt.Sprintf(`(version 1)
(deny default)
(allow syscall*)
(allow mach-bootstrap)
(import "bsd.sb")
(allow process-fork)
(allow process-exec*)

; Read + map the interpreter and its libraries. These are OS / software-install
; roots, never user data. (bsd.sb already covers /System, /usr/lib, /usr/share,
; the dyld shared cache, /dev, and the mach services needed to launch.)
(allow file-read* file-map-executable file-test-existence
       (subpath "/bin")
       (subpath "/sbin")
       (subpath "/usr/bin")
       (subpath "/usr/sbin")
       (subpath "/Library/Frameworks")   ; python.org & other framework installs
       (subpath "/Library/Developer")    ; Xcode Command Line Tools interpreters
       (subpath "/opt")                  ; Homebrew (Apple Silicon), MacPorts
       (subpath "/usr/local"))           ; Homebrew (Intel), /usr/local installs

; The sandbox scratch dir: the untrusted script itself + anything it writes.
(allow file-read* file-write* file-map-executable
       (subpath "%s"))

; Defense in depth over the base profile: it permits passwd/hosts DATA for
; libinfo, but user/group resolution actually goes through opendirectoryd over
; mach — so deny the file data (blocks e.g. reading /etc/passwd) while name
; lookups keep working. And deny all network egress.
(deny file-read-data (subpath "/private/etc"))
(deny network*)
`, realTmp)

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

    // Run inside the sandbox scratch dir. Otherwise the child inherits our cwd
    // (which may be under a now-denied location like the user's home), and even
    // getcwd(3) fails. This keeps the untrusted script confined to its own dir.
    cmd.Dir = realTmp

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
