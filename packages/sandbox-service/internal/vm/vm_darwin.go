//go:build darwin

package vm

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// reapByScratchCwd kills any process still holding scratchDir as its working
// directory. This catches a payload that detached via setsid()/a new session —
// which moves it out of our process group so kill(-pgid) can no longer reach it —
// because exec() preserves the inherited cwd (the sandbox runs the child with
// cwd = scratch). Best-effort: lsof is standard on macOS; if it is missing or
// matches nothing this is a no-op. Returns how many processes it killed so the
// caller can report honestly instead of asserting a clean exit while a detached
// descendant lives on. MUST run before the scratch dir is removed (lsof needs the
// path to still exist to walk it).
//
// This is the immediate cleanup; the inherited RLIMIT_CPU is the independent
// backstop that bounds a survivor which somehow evades this sweep (e.g. one that
// chdir'd away from scratch) — a CPU-bound survivor is killed by the kernel at
// the CPU limit even after setsid, and network/host-file access stays denied by
// the Seatbelt profile regardless.
func reapByScratchCwd(scratchDir string) int {
	killed := 0
	seen := map[int]bool{}
	// A detached child can take a few ms to appear after the direct parent returns
	// (fork -> setsid -> exec), so sweep a few times over a short window. Each pass
	// is cheap because scratch holds only a handful of files.
	for attempt := 0; attempt < 4; attempt++ {
		// -w suppresses warnings; -t prints PIDs only. IMPORTANT: lsof exits
		// NON-ZERO both when it matches nothing AND when it merely warns about a
		// path it couldn't stat, yet it still prints valid matches to stdout — so we
		// parse stdout regardless of the exit status (bailing on it silently drops
		// real survivors). We only skip a genuine start failure (cmd.Start error),
		// which surfaces as a non-ExitError.
		cmd := exec.Command("lsof", "-w", "-t", "-a", "-d", "cwd", "+D", scratchDir)
		out, err := cmd.Output()
		if err != nil {
			if _, isExit := err.(*exec.ExitError); !isExit {
				return killed // lsof missing / failed to start — best-effort, give up
			}
		}
		found := false
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			pid, perr := strconv.Atoi(line)
			if perr != nil || pid <= 1 || pid == os.Getpid() || seen[pid] {
				continue
			}
			found = true
			seen[pid] = true
			if syscall.Kill(pid, syscall.SIGKILL) == nil {
				killed++
			}
		}
		// Stop early once a pass is clean AND we've already caught something, or on
		// the first clean pass if nothing has shown up yet after a brief settle.
		if !found && (killed > 0 || attempt >= 1) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	return killed
}

// readCappedFile reads up to maxOutputBytes from an already-open output file,
// appending a truncation marker if there was more.
//
// It reads from the *open descriptor*, deliberately NOT by re-opening the path:
// the untrusted payload can unlink the file and drop a symlink at the same path,
// so re-opening would let our unsandboxed parent follow it and read an arbitrary
// host file. The fd stays bound to the inode the child actually wrote to.
func readCappedFile(f *os.File) string {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return ""
	}
	cb := newCapBuffer()
	// +1 so the cap buffer sees the overflow byte and records truncation.
	_, _ = io.Copy(cb, io.LimitReader(f, int64(maxOutputBytes)+1))
	return cb.String()
}

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

	// 0600: owner read/write only, no executable bit — the script is run by the
	// interpreter (python3/bash <file>), never exec'd, so it never needs +x.
	if err := os.WriteFile(codePath, []byte(req.Code), 0600); err != nil {
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

	interpreter := "bash"
	if req.Language == "python" {
		interpreter = "python3"
	}

	// Kernel resource limits (rlimits), applied via a `sh -c 'ulimit ...; exec ...'`
	// wrapper. rlimits are inherited across fork AND setsid, so unlike the
	// wall-clock timeout (which a detached process escapes) they also bound a
	// payload that tries to outlive the sandbox. Empirically on macOS:
	//   - RLIMIT_CPU  (ulimit -t): ENFORCED — bounds a runaway/detached CPU spinner.
	//   - RLIMIT_FSIZE(ulimit -f): ENFORCED — bounds a trivial disk-fill via a big file.
	//   - RLIMIT_NPROC(ulimit -u): ENFORCED but per-UID (counts ALL the user's
	//     processes), so we only ever LOWER it toward a ceiling when the current
	//     limit is comfortably above it — never below the user's real usage.
	//   - RLIMIT_AS   (ulimit -v): IGNORED by Darwin — a hard memory cap needs a
	//     container (the roadmap's gVisor/Landlock rung); we do NOT pretend to set it.
	timeoutSec := int(timeout / time.Second)
	if timeoutSec < 1 {
		timeoutSec = 1
	}
	// Generous CPU headroom over the wall clock so a legitimate multi-core burst
	// inside the timeout window isn't false-killed, while a process that detaches
	// (setsid) and escapes the wall-clock group kill is still bounded by the kernel.
	cpuSec := timeoutSec*2 + 5
	const fsizeKiB = 256 * 1024 // 256 MiB per file (macOS /bin/sh `ulimit -f` unit is KiB)

	// ulimit values are integers we compute (safe to interpolate). The interpreter
	// and script path are passed as positional args ($1,$2), never interpolated
	// into the shell text, so there is no quoting/injection surface. `exec` replaces
	// the shell with the interpreter, so the rlimits carry over and no extra shell
	// process lingers. The NPROC clause is defensive: it lowers only when the
	// current soft limit is a plain integer above the ceiling.
	limitScript := fmt.Sprintf(
		`ulimit -t %d 2>/dev/null; ulimit -f %d 2>/dev/null; `+
			`if u=$(ulimit -u 2>/dev/null); then case "$u" in ''|*[!0-9]*) : ;; *) [ "$u" -gt 2048 ] && ulimit -u 2048 2>/dev/null;; esac; fi; `+
			`exec "$1" "$2"`,
		cpuSec, fsizeKiB,
	)

	// Wrap with sandbox-exec: the Seatbelt profile is inherited across the sh->interp
	// exec, so the interpreter runs fully confined. /bin/sh is exec-allowed by the
	// profile's process-exec* /bin subpath.
	args := []string{"-f", profilePath, "/bin/sh", "-c", limitScript, "sh", interpreter, codePath}
	cmd := exec.CommandContext(execCtx, "sandbox-exec", args...)

	// Run inside the sandbox scratch dir. Otherwise the child inherits our cwd
	// (which may be under a now-denied location like the user's home), and even
	// getcwd(3) fails. This keeps the untrusted script confined to its own dir.
	cmd.Dir = realTmp

	// Give the child its own process group so we can kill the WHOLE tree — a
	// payload that spawns a subprocess (now allowed via process-exec*) would
	// otherwise leave orphans behind after we return. Cancel kills the group when
	// the timeout fires; the deferred kill sweeps up any survivors on every exit
	// path (e.g. the direct child exits early but left a background process).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}

	// Controlled, minimal environment — never inherit the host's secrets. See
	// buildSandboxEnv.
	cmd.Env = buildSandboxEnv(realTmp, req.Env)

	// Capture output to files, NOT os/exec pipes: a pipe write-end is inherited by
	// every descendant, so a lingering background subprocess would keep it open
	// and make cmd.Wait() block past the timeout. With files, Wait returns as soon
	// as the direct child exits. See readCappedFile.
	//
	// SECURITY: the scratch dir is writable by the untrusted payload, so it can
	// unlink these files and replace the paths with symlinks (e.g. to /etc/passwd).
	// We therefore (a) create them O_EXCL|O_NOFOLLOW so we never open a pre-planted
	// symlink, and (b) read the results back from the FILE DESCRIPTOR, never by
	// re-opening the path — the fd stays bound to the original inode, so a
	// path->symlink swap by the payload cannot make our (unsandboxed) parent read
	// an arbitrary host file. Reading by path here was a full sandbox-escape
	// exfiltration vector.
	const openFlags = os.O_RDWR | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW
	outF, err := os.OpenFile(filepath.Join(realTmp, ".wh_stdout"), openFlags, 0600)
	if err != nil {
		return nil, fmt.Errorf("create stdout file: %w", err)
	}
	defer outF.Close()
	errF, err := os.OpenFile(filepath.Join(realTmp, ".wh_stderr"), openFlags, 0600)
	if err != nil {
		return nil, fmt.Errorf("create stderr file: %w", err)
	}
	defer errF.Close()
	cmd.Stdout = outF
	cmd.Stderr = errF

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start sandbox process: %w", err)
	}
	// Tear down the process group on every exit path. This reaps the COMMON case
	// (background subprocesses that stay in our group). It does NOT reach a process
	// that called setsid()/created a new session to deliberately detach — that is
	// what reapByScratchCwd (by cwd) and the inherited RLIMIT_CPU (by kernel) are
	// for. -pid targets the group (Setpgid above).
	pgid := cmd.Process.Pid
	defer func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) }()

	err = cmd.Wait()

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

	// cmd.Wait() returns as soon as the DIRECT child exits — a payload can fork,
	// detach via setsid(), and return the parent immediately, which would otherwise
	// let it run on while we report a clean exit. Kill the group now, then sweep any
	// process that detached into a new session, identifying it by the scratch dir it
	// still holds as its cwd. This runs before the deferred RemoveAll so lsof can
	// still walk the path.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	reaped := reapByScratchCwd(realTmp)

	return &ExecResult{
		Stdout:         readCappedFile(outF),
		Stderr:         readCappedFile(errF),
		ExitCode:       exitCode,
		ExecutionMs:    time.Since(start).Milliseconds(),
		SandboxID:      s.id,
		Killed:         killed,
		DetachedReaped: reaped,
	}, nil
}

func (s *DarwinSandbox) Destroy(ctx context.Context) error {
	// Process exits instantly, no state to tear down
	return nil
}

func NewOSFactory() SandboxFactory {
	return &DarwinFactory{}
}
