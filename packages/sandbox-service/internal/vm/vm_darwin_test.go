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
	defer func() { _ = s.Destroy(context.Background()) }()
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

// Write-then-exec must be closed: a payload can WRITE into its scratch dir, but
// it must not be able to EXECUTE what it wrote. The scratch dir is the only
// writable location and is deliberately absent from the profile's process-exec*
// rule (and carries no file-map-executable), so dropping a binary and running it
// must fail — the classic /tmp write-then-run malware pattern.
func TestDarwinSandboxDeniesExecFromScratch(t *testing.T) {
	requirePython(t)
	res := runInSandbox(t, `
import os, subprocess
# copy a real binary into the writable scratch dir, mark it executable...
data = open('/bin/echo', 'rb').read()
open('dropped', 'wb').write(data)
os.chmod('dropped', 0o755)
# ...and try to run it from scratch — must be denied.
try:
    subprocess.run([os.path.join(os.getcwd(), 'dropped'), 'pwned'], check=True)
    print('EXEC_OK')
except Exception:
    print('EXEC_BLOCKED')
`)
	if strings.Contains(res.Stdout, "EXEC_OK") || !strings.Contains(res.Stdout, "EXEC_BLOCKED") {
		t.Fatalf("write-then-exec was NOT blocked: a scratch-written binary ran.\nstdout=%q\nstderr=%q", res.Stdout, res.Stderr)
	}
}

// The scoped process-exec* rule must not over-tighten: a legitimate subprocess of
// a binary living in an allowed system dir (/bin/echo) must still run, so the
// sandbox remains usable for real tools that shell out.
func TestDarwinSandboxAllowsSystemSubprocess(t *testing.T) {
	requirePython(t)
	res := runInSandbox(t, `
import subprocess
out = subprocess.run(['/bin/echo', 'hi'], capture_output=True, text=True)
print('SUBPROC', out.stdout.strip())
`)
	if !strings.Contains(res.Stdout, "SUBPROC hi") {
		t.Fatalf("benign system subprocess was blocked by over-tight process-exec.\nstdout=%q\nstderr=%q", res.Stdout, res.Stderr)
	}
}

// TimeoutMs must bound the WHOLE process tree. A payload that spawns a
// background subprocess must not be able to extend its run past the timeout, and
// no orphaned subprocess may survive after the sandbox returns. Regression for
// the os/exec pipe-inheritance hang + process-group reaping.
func TestDarwinSandboxTimeoutReapsSubprocessTree(t *testing.T) {
	requirePython(t)
	const marker = "864213" // unusual sleep duration so we can spot our orphan
	s, err := (&DarwinFactory{}).Create(context.Background())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = s.Destroy(context.Background()) }()

	res, err := s.Execute(context.Background(), ExecRequest{
		Code:      "import subprocess, time\nsubprocess.Popen(['/bin/sleep', '" + marker + "'])\nprint('SPAWNED', flush=True)\ntime.sleep(999)",
		Language:  "python",
		TimeoutMs: 500,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Killed {
		t.Fatalf("expected Killed=true when the timeout fires, got %+v", res)
	}
	if res.ExecutionMs > 3000 {
		t.Fatalf("timeout not enforced: ran %dms — a subprocess must not extend it", res.ExecutionMs)
	}
	if out, _ := exec.Command("pgrep", "-f", "sleep "+marker).Output(); strings.TrimSpace(string(out)) != "" {
		_ = exec.Command("pkill", "-f", "sleep "+marker).Run()
		t.Fatalf("timeout leaked an orphaned subprocess: pids=%q", strings.TrimSpace(string(out)))
	}
}

// The untrusted process must NOT inherit the host's environment (which routinely
// holds API keys / cloud credentials). Only a controlled base + caller-supplied
// vars should be visible.
func TestDarwinSandboxDoesNotLeakParentEnv(t *testing.T) {
	requirePython(t)
	t.Setenv("WHA_TEST_SECRET", "leaked-value-42")
	res := runInSandbox(t, `
import os
print('SECRET_VISIBLE' if os.environ.get('WHA_TEST_SECRET') else 'SECRET_HIDDEN')
`)
	if !strings.Contains(res.Stdout, "SECRET_HIDDEN") {
		t.Fatalf("parent environment leaked into the sandbox (or script failed).\nstdout=%q\nstderr=%q", res.Stdout, res.Stderr)
	}
}

// Output must be capped so a payload can't exhaust host memory by printing
// without bound.
func TestDarwinSandboxCapsOutput(t *testing.T) {
	requirePython(t)
	res := runInSandbox(t, "print('A'*(20*1024*1024))") // 20 MiB, over the cap
	if len(res.Stdout) > maxOutputBytes+1024 {
		t.Fatalf("stdout was not capped: %d bytes", len(res.Stdout))
	}
	if !strings.Contains(res.Stdout, "output truncated") {
		t.Fatalf("expected a truncation marker; got %d bytes without one", len(res.Stdout))
	}
}

// End-to-end proof that dangerous caller-supplied env vars are dropped at the
// sandbox boundary: a payload must not be able to smuggle in interpreter/linker
// hijacking variables via req.Env, while a benign allow-listed var still arrives.
func TestDarwinSandboxDropsDangerousEnv(t *testing.T) {
	requirePython(t)
	s, err := (&DarwinFactory{}).Create(context.Background())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = s.Destroy(context.Background()) }()

	res, err := s.Execute(context.Background(), ExecRequest{
		Code: `
import os
print('PYPATH', os.environ.get('PYTHONPATH'))
print('DYLD', os.environ.get('DYLD_INSERT_LIBRARIES'))
print('LC', os.environ.get('LC_ALL'))
`,
		Language: "python",
		Env: map[string]string{
			"PYTHONPATH":            "/tmp/evil",
			"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
			"LC_ALL":                "en_US.UTF-8",
		},
		TimeoutMs: 5000,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(res.Stdout, "PYPATH None") {
		t.Fatalf("PYTHONPATH was not dropped:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "DYLD None") {
		t.Fatalf("DYLD_INSERT_LIBRARIES was not dropped:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "LC en_US.UTF-8") {
		t.Fatalf("allow-listed LC_ALL did not pass through:\n%s", res.Stdout)
	}
}

// The output files live in the writable scratch dir, so a payload can unlink
// them and drop a symlink to a host file at the same path. The parent reads
// results back from the fd (not by re-opening the path), so it must NOT follow
// such a symlink and leak /etc/passwd into the captured output. Regression for a
// confused-deputy sandbox-escape exfiltration.
func TestDarwinSandboxOutputFileSymlinkNoExfil(t *testing.T) {
	requirePython(t)
	res := runInSandbox(t, `
import os
for name in ('.wh_stdout', '.wh_stderr'):
    try:
        os.remove(name)
    except OSError:
        pass
    try:
        os.symlink('/etc/passwd', name)
    except OSError:
        pass
print('PAYLOAD_MARKER')
`)
	if strings.Contains(res.Stdout, "root:") || strings.Contains(res.Stderr, "root:") {
		t.Fatalf("output-file symlink swap leaked a host file.\nstdout=%q\nstderr=%q", res.Stdout, res.Stderr)
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
