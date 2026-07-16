//go:build darwin

package vm

import (
	"bytes"
	"fmt"
	"os"
	"sort"
)

// maxOutputBytes caps how much stdout/stderr the sandbox will buffer per stream.
// Without a cap, an untrusted script can print without bound and exhaust the
// host's memory (a DoS), which matters even more because the wall-clock timeout
// can be extended by the payload. 10 MiB is generous for tool output.
const maxOutputBytes = 10 << 20

// capBuffer is an io.Writer that stores at most `limit` bytes and then silently
// discards the rest, recording that truncation happened. It never returns an
// error from Write: a short write would make os/exec kill the pipe copier and
// surface confusing failures, so we always report the full length as written.
type capBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newCapBuffer() *capBuffer { return &capBuffer{limit: maxOutputBytes} }

func (c *capBuffer) Write(p []byte) (int, error) {
	if remaining := c.limit - c.buf.Len(); remaining > 0 {
		if len(p) <= remaining {
			return c.buf.Write(p)
		}
		c.buf.Write(p[:remaining])
	}
	if c.buf.Len() >= c.limit {
		c.truncated = true
	}
	return len(p), nil
}

// String returns the captured output, appending a marker if it was truncated so
// the caller can tell output was dropped rather than the script producing that.
func (c *capBuffer) String() string {
	if c.truncated {
		return c.buf.String() + fmt.Sprintf("\n[output truncated at %d bytes]", c.limit)
	}
	return c.buf.String()
}

// envAllowlist is the set of caller-suppliable variables (from req.Env) that are
// safe to pass into the sandbox. Anything not on this list is dropped.
//
// This is an allow-list, not a deny-list, on purpose: the dangerous variables are
// the dynamic-linker and interpreter-startup ones (DYLD_INSERT_LIBRARIES,
// DYLD_LIBRARY_PATH, LD_PRELOAD, PYTHONPATH, PYTHONSTARTUP, PYTHONHOME, BASH_ENV,
// ENV, ...) that let a caller inject code or weaken the interpreter's security
// posture, and a deny-list will always miss one. PATH, HOME and TMPDIR are set by
// the sandbox itself and are deliberately NOT overridable — letting the caller
// set PATH would redirect interpreter resolution, and HOME would redirect config
// reads.
var envAllowlist = map[string]bool{
	"LANG":     true,
	"LC_ALL":   true,
	"LC_CTYPE": true,
	"TZ":       true,
	"TERM":     true,
}

// buildSandboxEnv returns the environment for the untrusted process.
//
// It deliberately does NOT inherit the parent's full environment: that process
// tree runs the host user's shell, so os.Environ() routinely holds secrets
// (API keys, cloud credentials) that an untrusted payload must never read via
// os.environ. We start from a minimal controlled base and overlay only the
// allow-listed caller-supplied vars:
//   - PATH is preserved so the interpreter (python3/bash) still resolves the
//     same way it does outside the sandbox;
//   - HOME and TMPDIR point at the writable scratch dir, so tools that write
//     dotfiles or temp files stay confined instead of failing or escaping.
func buildSandboxEnv(scratchDir string, reqEnv map[string]string) []string {
	merged := map[string]string{
		"PATH":   os.Getenv("PATH"),
		"HOME":   scratchDir,
		"TMPDIR": scratchDir,
		"LANG":   "en_US.UTF-8",
	}
	for k, v := range reqEnv {
		if envAllowlist[k] {
			merged[k] = v
		}
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic order
	env := make([]string, 0, len(merged))
	for _, k := range keys {
		env = append(env, fmt.Sprintf("%s=%s", k, merged[k]))
	}
	return env
}
