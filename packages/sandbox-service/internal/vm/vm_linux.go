//go:build linux
package vm

import (
    "context"
    "fmt"
    "os"
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
        "landlock sandbox backend is not implemented: refusing to execute untrusted code without isolation. " +
            "No Linux backend currently provides real isolation (the gvisor backend also fails closed); " +
            "use the macOS backend for now, or wait for the Landlock/namespace implementation")
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

// Execute FAILS CLOSED.
//
// The previous implementation ran `runsc do <interpreter> <script>`, which
// intercepts syscalls but by default maps the host filesystem into the sandbox
// and leaves network egress open — so it restricts syscalls yet does NOT hide
// host file contents. That is the same false-sense-of-containment problem the
// Landlock backend refuses to ship. Until the payload runs from a minimal OCI
// bundle with an isolated rootfs (only the scratch dir bind-mounted) and
// `--network=none`, we refuse to execute.
func (s *GvisorSandbox) Execute(ctx context.Context, req ExecRequest) (*ExecResult, error) {
    return nil, fmt.Errorf(
        "gvisor backend does not provide filesystem/network isolation yet " +
            "(runsc do exposes the host filesystem and leaves network open): " +
            "refusing to execute untrusted code")
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
