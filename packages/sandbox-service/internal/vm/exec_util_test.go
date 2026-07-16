//go:build darwin

package vm

import (
	"strings"
	"testing"
)

// capBuffer must store at most `limit` bytes and flag truncation, and it must
// never return a short write (which would make os/exec kill the pipe copier).
func TestCapBuffer(t *testing.T) {
	c := &capBuffer{limit: 10}
	n, err := c.Write([]byte("12345"))
	if n != 5 || err != nil {
		t.Fatalf("write within limit: n=%d err=%v", n, err)
	}
	// Over-limit write: full length reported, content capped, truncated flagged.
	n, err = c.Write([]byte("ABCDEFGHIJ"))
	if n != 10 || err != nil {
		t.Fatalf("over-limit write must report full length: n=%d err=%v", n, err)
	}
	if !c.truncated {
		t.Fatalf("expected truncated=true after exceeding limit")
	}
	s := c.String()
	if !strings.HasPrefix(s, "12345ABCDE") {
		t.Fatalf("capped content wrong: %q", s)
	}
	if !strings.Contains(s, "output truncated") {
		t.Fatalf("expected truncation marker in %q", s)
	}
}

// buildSandboxEnv must not carry arbitrary host vars, must keep PATH, must point
// HOME/TMPDIR at the scratch dir, must pass allow-listed caller vars, and must
// DROP dangerous / non-allow-listed caller vars (dynamic-linker + interpreter
// hijacking) as well as caller attempts to override PATH/HOME.
func TestBuildSandboxEnv(t *testing.T) {
	t.Setenv("WHA_SHOULD_NOT_LEAK", "secret")
	env := buildSandboxEnv("/scratch/xyz", map[string]string{
		"LC_ALL":                "en_US.UTF-8", // allow-listed -> kept
		"FOO":                   "bar",         // not allow-listed -> dropped
		"DYLD_INSERT_LIBRARIES": "/scratch/xyz/evil.dylib",
		"LD_PRELOAD":            "/scratch/xyz/evil.so",
		"PYTHONPATH":            "/scratch/xyz",
		"PYTHONSTARTUP":         "/scratch/xyz/evil.py",
		"BASH_ENV":              "/scratch/xyz/evil.sh",
		"PATH":                  "/scratch/xyz", // caller must NOT override PATH
		"HOME":                  "/evil",        // caller must NOT override HOME
	})
	joined := strings.Join(env, "\n")

	for _, want := range []string{"HOME=/scratch/xyz", "TMPDIR=/scratch/xyz", "LC_ALL=en_US.UTF-8"} {
		if !strings.Contains(joined, want) {
			t.Errorf("env missing %q in:\n%s", want, joined)
		}
	}
	if !strings.Contains(joined, "PATH=") || strings.Contains(joined, "PATH=/scratch/xyz") {
		t.Errorf("PATH must be sandbox-controlled, not caller-overridable:\n%s", joined)
	}
	if strings.Contains(joined, "HOME=/evil") {
		t.Errorf("caller overrode HOME:\n%s", joined)
	}
	for _, forbidden := range []string{
		"WHA_SHOULD_NOT_LEAK", "FOO=bar",
		"DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "PYTHONPATH", "PYTHONSTARTUP", "BASH_ENV",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("env leaked forbidden variable %q:\n%s", forbidden, joined)
		}
	}
}
