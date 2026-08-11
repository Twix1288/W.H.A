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

	// AllowPaths are host subtrees the caller (via the envelope) has explicitly
	// opened to the sandboxed process, on TOP of the always-private scratch dir.
	// This is what turns `run` from a hermetic throwaway box into "run my real
	// tool, scoped to this project": a read-only or read-write grant on a specific
	// directory while every sibling and the rest of the host stay denied by
	// omission. Each path is canonicalized by the backend so `..`/symlink tricks
	// cannot widen the grant, and grants are read/write only — never
	// exec/map-executable — so a mounted dir can't become a write-then-exec vector.
	AllowPaths []PathRule

	// EgressProxy, if set ("host:port"), is the ONLY network destination the
	// sandboxed process may reach; all other egress stays denied. Seatbelt cannot
	// match egress by hostname (DNS is denied inside the sandbox), so the
	// enforceable model is "allow only a local vetting proxy" — the proxy is where
	// hostname allow-listing and secret brokering happen. Empty = deny all egress.
	EgressProxy string

	// NOT YET ENFORCED. These are accepted for forward-compatibility but no
	// backend currently applies a hard memory or CPU limit: reliable per-process
	// limits need cgroups on Linux (pending the Linux backend) and are not
	// dependable on macOS (Darwin largely ignores RLIMIT_AS). Today the actual
	// resource bounds are the wall-clock timeout (TimeoutMs) and the per-stream
	// output cap (see maxOutputBytes). Do not rely on these fields for isolation.
	MaxMemMB  int
	MaxCPUPct float64
}

// PathRule is a single caller-opened host subtree. Write=false grants read-only
// access; Write=true grants read+write. Never grants execute/map-executable.
type PathRule struct {
	Path  string
	Write bool
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
	Stdout      string
	Stderr      string
	ExitCode    int
	ExecutionMs int64
	SandboxID   string
	Killed      bool

	// DetachedReaped counts processes that detached from our process group
	// (e.g. via setsid()/a new session) and had to be swept up by cwd after the
	// direct child returned. A non-zero value means the payload tried to outlive
	// the sandbox: the result is NOT a clean, self-contained completion. Callers
	// should surface it rather than report an unqualified success.
	DetachedReaped int
}

type OSProcessSandbox interface {
	ID() string
	Execute(ctx context.Context, req ExecRequest) (*ExecResult, error)
	Destroy(ctx context.Context) error
}

type SandboxFactory interface {
	Create(ctx context.Context) (OSProcessSandbox, error)
}
