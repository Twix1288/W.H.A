//go:build darwin
package vm

import (
    "context"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
    "testing"
)

func requirePython(t *testing.T) {
    t.Helper()
    if _, err := exec.LookPath("python3"); err != nil {
        t.Skip("python3 not available; skipping sandbox integration test")
    }
}

func runInSandbox(t *testing.T, code string) *ExecResult {
    t.Helper()
    s, err := (&DarwinFactory{}).Create(context.Background())
    if err != nil {
        t.Fatalf("create sandbox: %v", err)
    }
    defer s.Destroy(context.Background())
    res, err := s.Execute(context.Background(), ExecRequest{
        Code:      code,
        Language:  "python",
        TimeoutMs: 5000,
    })
    if err != nil {
        t.Fatalf("execute: %v", err)
    }
    return res
}

// Regression test for the host-file-read breakout.
//
// Before the fix, the generated Seatbelt profile contained a bare
// `(allow file-read*)`, so an untrusted script running under `wh-agent run`
// could read ANY file on the host (SSH keys, cloud creds, /etc/passwd, ...)
// and return the contents to the caller. This pins the fix: a protected host
// file outside the sandbox scratch dir must be denied.
func TestDarwinSandboxDeniesHostFileRead(t *testing.T) {
    requirePython(t)
    res := runInSandbox(t, `
try:
    data = open('/etc/passwd').read()
    print('READ_OK', len(data))
except Exception:
    print('BLOCKED')
`)
    if strings.Contains(res.Stdout, "READ_OK") || !strings.Contains(res.Stdout, "BLOCKED") {
        t.Fatalf("sandbox breakout: host file read was NOT blocked.\nstdout=%q\nstderr=%q", res.Stdout, res.Stderr)
    }
}

// Proves the profile is a genuine ALLOW-LIST (deny-by-omission), not just a few
// hard-coded denies: a secret in an unrelated temp dir — a path the profile
// never mentions — must be unreadable from inside the sandbox.
func TestDarwinSandboxDeniesArbitraryHostRead(t *testing.T) {
    requirePython(t)

    dir, err := os.MkdirTemp("", "wha-host-secret-*")
    if err != nil {
        t.Fatalf("mkdtemp: %v", err)
    }
    defer os.RemoveAll(dir)
    secret := filepath.Join(dir, "secret.txt")
    if err := os.WriteFile(secret, []byte("TOP-SECRET-DECOY"), 0600); err != nil {
        t.Fatalf("write secret: %v", err)
    }

    res := runInSandbox(t, `
try:
    print('LEAKED', open(`+strconv.Quote(secret)+`).read())
except Exception:
    print('BLOCKED')
`)
    if strings.Contains(res.Stdout, "LEAKED") || !strings.Contains(res.Stdout, "BLOCKED") {
        t.Fatalf("allow-list breach: arbitrary host file was readable.\nstdout=%q\nstderr=%q", res.Stdout, res.Stderr)
    }
}

// The hardened profile must still let a legitimate tool read and write inside
// its own scratch directory, or the sandbox would be useless.
func TestDarwinSandboxAllowsScratchIO(t *testing.T) {
    requirePython(t)
    res := runInSandbox(t, `
import os
open('out.txt', 'w').write('ok')
print('WORK_OK', os.path.exists('out.txt'), open('out.txt').read())
`)
    if !strings.Contains(res.Stdout, "WORK_OK True ok") {
        t.Fatalf("benign scratch I/O failed under sandbox.\nstdout=%q\nstderr=%q", res.Stdout, res.Stderr)
    }
}

// Denying host-file reads must NOT break OS name resolution: user/group lookups
// go through opendirectoryd (mach), not by reading /etc/passwd. Guards against a
// future over-tightening that would make the sandbox unusable for real tools.
func TestDarwinSandboxNameResolutionSurvives(t *testing.T) {
    requirePython(t)
    res := runInSandbox(t, `
import os, pwd
try:
    print('NAME', pwd.getpwuid(os.getuid()).pw_name)
except Exception as e:
    print('NAME_FAILED', type(e).__name__)
`)
    if !strings.Contains(res.Stdout, "NAME ") || strings.Contains(res.Stdout, "NAME_FAILED") {
        t.Fatalf("name resolution broke under sandbox.\nstdout=%q\nstderr=%q", res.Stdout, res.Stderr)
    }
}
