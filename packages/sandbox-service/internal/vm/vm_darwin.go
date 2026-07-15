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
    defer func() {
        // Don't drop cleanup failures: this dir holds the untrusted script and
        // anything it wrote, so a silent leave-behind is an info-disclosure gap.
        if rerr := os.RemoveAll(tmpDir); rerr != nil {
            fmt.Fprintf(os.Stderr, "failed to clean up sandbox scratch dir %s: %v\n", tmpDir, rerr)
        }
    }()

    // 2. Write the code to a file. Language is validated at ingestion, but treat
    // an unknown value as a hard error here too so a bad value can never reach a
    // shell even if a future caller bypasses that check.
    codePath := filepath.Join(tmpDir, "script")
    switch req.Language {
    case "python":
        codePath += ".py"
    case "bash", "":
        codePath += ".sh"
    default:
        return nil, fmt.Errorf("unsupported language %q", req.Language)
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
    // Confinement correctness depends on the canonical path, so fail closed
    // rather than silently downgrading to an unresolved path if resolution fails.
    realTmp, symErr := filepath.EvalSymlinks(tmpDir)
    if symErr != nil {
        return nil, fmt.Errorf("resolve sandbox scratch dir for confinement: %w", symErr)
    }

    profile := fmt.Sprintf(`(version 1)
(deny default)
(import "bsd.sb")
(allow process-fork)

; No blanket "(allow syscall*)" or "(allow mach-bootstrap)": bsd.sb already
; grants the syscalls and mach name-resolution services the interpreter needs to
; launch. Verified empirically that python3 launch, name resolution, and scratch
; I/O all work without them, so the syscall/mach surface stays at default-deny
; instead of being widened wholesale.

; Execute only from OS / software-install roots — NEVER from the scratch dir.
; The scratch subpath (below) is the sole writable location, so omitting it here
; is what closes the write-then-exec vector: a payload can drop a binary in
; scratch but cannot run it. These trees aren't writable under this profile, so a
; subpath allow here can't be satisfied by a written-then-renamed file either.
(allow process-exec*
       (subpath "/bin")
       (subpath "/sbin")
       (subpath "/usr/bin")
       (subpath "/usr/sbin")
       (subpath "/Library/Frameworks")
       (subpath "/Library/Developer")
       (subpath "/opt")
       (subpath "/usr/local"))

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
; Deliberately NO file-map-executable here, and this path is absent from the
; process-exec* rule above — scripts are interpreted (passed as an arg to
; python3/bash), never mapped or exec'd, so a file written here can be read and
; written but never loaded as code.
(allow file-read* file-write*
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
    switch req.Language {
    case "python":
        cmdArgs = []string{"python3", codePath}
    default: // "bash" or "" (validated upstream)
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
