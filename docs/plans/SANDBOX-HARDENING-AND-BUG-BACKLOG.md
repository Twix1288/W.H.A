# Sandbox Hardening & Bug Backlog

Status: **proposed** · Date: 2026-08-03 · Scope: `wh-agent run` + the Go sandbox, plus verified bugs in already-shipped features

**Positioning is unchanged.** W.H.Agent remains "an antivirus and execution sandbox for your local AI agents." The design-partner notes referenced below were *supportive* and are used here strictly as **technical input on sandboxing** — a practitioner describing which containment properties matter in practice. They are not a reason to change the product's frame or its market.

Everything in Part 1 was executed against the real built binary on macOS 26.5 (arm64), not inferred from code.

---

## Part 1 — What the sandbox actually does (verified by execution)

Built `packages/cli/bin/wh-sandbox` and drove it directly with `ExecRequest` JSON on stdin.

### 1.1 Guarantees that hold ✅

These are real and worth using as proof points — each was attacked and held:

| Attack | Result |
|---|---|
| Read `~/.ssh` | Denied — and reported **`ENOENT`, not `EPERM`**, because `HOME` is remapped to the scratch dir. Existence is masked, not just access. |
| Read `/etc/passwd` | `PermissionError: Operation not permitted` |
| Network egress (`urllib`) | Blocked at DNS — `gaierror: nodename nor servname provided` |
| **Write-then-execute in scratch** | **Blocked** — `chmod +x` then exec gives `PermissionError`. The core guarantee holds. |
| Write into `/opt/homebrew/bin` from inside | Denied |
| `sudo` | Exec denied (`Operation not permitted`) |
| Keychain (`security list-keychains`, `dump-keychain`) | Effectively blocked — `SecKeychainCopySearchList` fails with invalid-parameter |
| Cross-app Apple Events (`System Events` → process list) | Blocked (error `-10827`) |
| `osascript -e 'do shell script "..."'` | **Not an escape.** The spawned shell inherits Seatbelt confinement: `/etc/passwd` denied, `~/.ssh` resolves into scratch, egress blocked. A `touch ~/marker` printed success but wrote into scratch — it never touched the real home. |
| Timeout | Enforced. `TimeoutMs: 3000` → killed at 3002ms, `Killed: true`. |
| Orphan sweep for same-process-group children | Works — `kill(-pgid)` reaps them. |
| Scratch dir cleanup | Works — no leftover `sandbox-*` dirs. |

The `osascript` result is worth calling out: `do shell script` is the classic macOS sandbox-bypass primitive, and it does **not** bypass this profile. That is a genuinely strong result.

### 1.2 Confirmed bugs ❌

**S1 — CRITICAL: `setsid` defeats both the process-group kill and the wall-clock timeout.**

A payload that detaches with `setsid` (Python `start_new_session=True`) survives the sandbox indefinitely, and the sandbox reports **clean success**.

```
sandbox: Stdout="spawned DETACHED child (setsid)"  Killed=false  ExitCode=0  ExecutionMs=294
3s after sandbox exit:
  PID   PPID  PGID   SESS  COMMAND
  53800    1  53800     0  whescape777 25      ← still running, reparented to launchd
control (no setsid): ✓ correctly killed
```

The teardown is `syscall.Kill(-pgid, SIGKILL)` ([vm_darwin.go:244](../../packages/sandbox-service/internal/vm/vm_darwin.go#L244)). `setsid` puts the child in a **new** session and process group, so `-pgid` cannot reach it. The code comment at lines 241-243 promises *"Tear down the whole process group no matter how we leave, so no orphaned grandchild survives the sandbox"* — that guarantee is false.

Accurate severity: the survivor **remains Seatbelt-confined**, so this is not a data-exfiltration escape. It is a **teardown/timeout escape**: unbounded persistent execution while the caller is told the run completed cleanly. For a sandbox that advertises timeout enforcement and process-tree teardown, that's critical.

Note this was missed by the existing test suite *and* by my first attempt — my initial probe used `subprocess.Popen` (same process group, correctly reaped) and a `/tmp` marker file the sandbox rightly denied, which masked the result. Detection required enumerating processes from outside. **Any regression test for this must assert on process survival, not on a file marker.**

**S2 — HIGH: no memory, CPU, process-count, or disk limits.**

- Allocated **1.5 GB** inside the sandbox: `Killed: false`, no limit hit.
- Wrote **300 MB** into scratch: no quota; a payload can fill the volume backing `/var/folders`.
- The profile grants `(allow process-fork)` with no process cap, so a fork bomb is unbounded. *(Not executed — it would destabilize the host. Treat as untested-but-implied by S2 and the absence of any rlimit.)*

`MaxMemMB` / `MaxCPUPct` are accepted in `ExecRequest` and documented as unenforced ([vm.go:16-22](../../packages/sandbox-service/internal/vm/vm.go#L16-L22)). Honest, but it means the sandbox contains *access* and not *consumption* — and combined with S1, a detached fork bomb outlives the run.

**S3 — MEDIUM: exec is allowed from user-writable paths.**

The profile allows `process-exec*` over `/opt` and `/usr/local` ([vm_darwin.go:126-134](../../packages/sandbox-service/internal/vm/vm_darwin.go#L126-L134)). On a standard Homebrew Mac:

```
drwxrwxr-x  258 rahulagnihotri  admin  /opt/homebrew/bin     ← user-writable
```

Verified: a binary pre-planted there (by anything running as the user, outside the sandbox) **executes inside the sandbox**. The payload can't plant it itself (S1.1 confirms writes are denied), so this is not a self-escape — but it means the exec allow-list trusts a directory that any other process on the machine, including another unsandboxed agent, can write to. That undercuts the write-then-exec guarantee across invocations.

**S4 — LOW: host identity leak.** `socket.gethostname()` → `Rahuls-MacBook-Air.local` (owner's name), `os.getuid()` → `505`, `platform.platform()` → full OS/arch, and `osascript -e 'return POSIX path of (path to home folder)'` → `/Users/rishitagnihotri/` (real username, despite `HOME` being remapped). `ps aux` is correctly blocked.

---

## Part 2 — Sandbox hardening plan

Ordered by severity, and by what unblocks the sandbox actually being usable for real agent work.

### H1 — Fix the teardown escape (S1) · ~3 days

macOS has no cgroups or PID namespaces, so there is no single-syscall fix. Practical approach:

1. **Track descendants during execution.** Poll the process table (`sysctl KERN_PROC_ALL`) on an interval while the child runs, recording every PID whose ancestry traces to our direct child. Kill that explicit PID set at teardown, in addition to `kill(-pgid)`.
2. **Verify before reporting success.** After teardown, re-enumerate; if any tracked PID survives, set a new `Escaped bool` on `ExecResult` and surface it loudly. Never report `Killed: false, ExitCode: 0` when a descendant is still alive.
3. **Belt-and-braces:** each run already has a unique scratch path; cross-check for any process holding it open before deleting the dir.
4. Consider whether `(allow process-fork)` is needed at all for the default profile. If subprocess support is opt-in per envelope, the default profile can drop fork and close this class entirely.

**Regression test:** spawn a `setsid` child, assert it is gone after the run, and assert `Escaped == false`. Must assert on process existence, not a marker file (see S1).

### H2 — Enforce resource limits (S2) · ~4 days

Set `RLIMIT_AS` (address space), `RLIMIT_CPU`, `RLIMIT_NPROC`, and `RLIMIT_FSIZE` on the child via `SysProcAttr` before exec, driven by `MaxMemMB`/`MaxCPUPct` plus a new `MaxProcs`/`MaxDiskMB`. Darwin ignores some rlimits inconsistently — measure each one and **document precisely which are enforced**, rather than accepting fields that do nothing. Add a scratch-dir size check to the existing output-cap logic.

### H3 — Tighten exec roots (S3) · ~2 days

Stop blanket-allowing `/opt` and `/usr/local`. Instead resolve the *specific* interpreter the run needs (`python3`, `bash`) and allow exec only for its canonical realpath plus its library root. Where a needed root is group- or user-writable, either warn at startup or require it to be named explicitly in the envelope. Keep `/bin` and `/usr/bin` (root-owned).

### H4 — Make the envelope real: caller-specified path scoping · ~2 weeks

This is the biggest functional gap, and it is what makes `run` usable for real work rather than only for hermetic throwaway scripts.

**Today:** `envelope.yaml` declares filesystem mounts, `network.allowed_destinations`, `credentials.inject_mode: memory_only`, and telemetry — and **none of it is parsed.** `runAgent`'s second parameter is `_envelopePath`, underscore-prefixed and discarded ([run.ts:6-10](../../packages/cli/src/commands/run.ts#L6-L10)). The Seatbelt profile is a hardcoded format string whose only interpolated value is the ephemeral scratch dir. So the sandbox doesn't *constrain* access to a project — it has *zero* access to any project.

**Feasibility is proven.** I verified on this machine that Seatbelt supports exactly what's needed, with no directory restructuring:

| Spike test | Result |
|---|---|
| Allow one project subtree, read a file in it | ✅ readable |
| Read a **sibling** directory | ✅ `EPERM` |
| **Enumerate** the parent directory | ✅ denied |
| Read `~/.ssh` | ✅ denied (`ENOENT` — existence masked) |
| Direct internet egress | ✅ blocked (`http_code=000`) |
| Egress to a local broker on `127.0.0.1:8888` | ✅ allowed (`200`) |
| **`node` (a real long-lived agent runtime) under the scoped profile** | ✅ runs; project file readable; sibling `EPERM`; `~/.ssh` denied |

Work:
1. Parse the envelope (zod schema) in `run.ts`; delete or implement `--envelope` — today it appears in `--help` and does nothing.
2. Add `AllowPaths []PathRule` to `ExecRequest`; template into the profile as `(allow file-read*/file-write* (subpath ...))`.
3. Canonicalize **every** path with `filepath.EvalSymlinks` (mirroring the existing `realTmp` handling) so `..` and symlink tricks can't widen a grant. Deny wins on overlap. Reject rules resolving above the declared project root.
4. Unhardcode `TimeoutMs: 5000`; add argv passthrough; widen language support beyond Python/Bash.

Note the constraint that falls out of the spike: **Seatbelt has no hostname-based network filtering** — only IP/port. So host/path/method policy must live in a local broker process, not in the profile. The profile's job is to permit exactly one socket.

### H5 — Egress brokering (proves out `allowed_destinations`) · ~2 weeks

Local CONNECT proxy; profile allows only `(allow network-outbound (remote ip "localhost:<port>"))`; `HTTPS_PROXY` injected via `buildSandboxEnv`. Enforce host/port rules from the envelope, default-deny, audit every allow and deny. Add first-seen-destination approval — without it, default-deny is just "offline," which nobody keeps enabled.

### H6 — Reduce identity leak (S4) · ~1 day

Low priority, but cheap: override `HOSTNAME`, and evaluate whether the `bsd.sb` sysctl surface can be narrowed without breaking interpreter startup. Accept the residual leak and **document it** rather than implying full anonymity.

### H7 — Linux parity · ~3-4 weeks

Implement the real Landlock ruleset sketched at [vm_linux.go:34-40](../../packages/sandbox-service/internal/vm/vm_linux.go#L34-L40) so H4 path rules apply identically; pair with a netns plus the H5 broker. Keep failing closed until it genuinely enforces — the current fail-closed behavior is correct and should not be softened.

---

## Part 3 — Verified bugs in already-shipped features

From reading the shipped import graph (`src/index.ts` and its transitive closure). Both suites currently pass — `go test ./...` green, 21 bun tests green, `tsc --noEmit` clean — so none of these are caught today.

**B1 — HIGH: `run` prints isolation guarantees that can be false.** `[NETWORK] Default-Deny enforced`, `[STORAGE] Root filesystem restricted`, and `[ISOLATION] Sub-millisecond OS-Native isolation active` are unconditional `console.log`s emitted *before* the sandbox binary is even located ([run.ts:58-62](../../packages/cli/src/commands/run.ts#L58-L62)). On Linux/Windows the backend then fails closed and runs nothing — but the user was already told isolation was active. "Sub-millisecond" is never measured. **Fix:** have `wh-sandbox` report its selected backend and capability set in the result JSON; print facts after execution, nothing on a fail-closed platform, and drop the latency claim.

**B2 — HIGH: `Read(*)`, `Glob(*)`, `Grep(*)`, `LS(*)` produce zero findings.** `OVERLY_PERMISSIVE` ([permissions.ts:16-126](../../packages/cli/src/core-scanner/rules/permissions.ts#L16-L126)) has `^Write\(\*\)$` and `^Edit\(\*\)$` but no read/enumerate equivalent. Unbounded-*path* grants (`Read(~/*)`, `Read(/*)`) **are** caught; unbounded-*tool* grants are not. Worse, [permissions.ts:806](../../packages/cli/src/core-scanner/rules/permissions.ts#L806) *recommends* `"allow": ["Read(*)", "Glob(*)", "Grep(*)"]` as remediation, and `init/index.ts:42` scaffolds `Read(*)` as a "secure default" — so the scanner advises the exact over-broad read scope it should flag. This is the "an agent enumerated everything on my laptop" failure mode, and we'd currently pass a config that permits it. **Fix:** add the four tool-wildcard patterns; widen broad-path matching to `(**/*)` and `(~/**)`; change the suggestion and the `init` default to a scoped `Read(./src/**)`.

**B3 — MEDIUM: dead flags in `--help`.** `--envelope` (H4), `--registry-url` (registry host hardcoded at install.ts:45, so a private-registry user silently gets npmjs.org metadata), `--allow-low-score` (no consumer; the `ConformanceScorer` it would override is unreachable, so no score is ever computed). In a security tool a flag that appears to constrain behavior and doesn't is a correctness bug. **Fix:** implement or delete, and add a CI check that fails on a registered flag with no consumer.

**B4 — MEDIUM: duplicated reporter logic.** `scan.ts` reimplements `formatJson`/`formatMarkdown`/`formatSarif` inline (around lines 86-127) while fuller implementations sit unreachable: `reporter/sarif.ts` (302 lines), `reporter/json.ts` (173), `reporter/html.ts` (1,152). Two SARIF emitters means one is untested and will drift. **Fix:** delete the inline versions, wire the real reporters, and validate output against SARIF 2.1.0.

**B5 — MEDIUM: a complete tool-call policy engine is written but unreachable.** `core-scanner/runtime/` (722 lines) implements PreToolUse deny rules with tool+regex matching, rate limits, an NDJSON audit log, a hook installer, and a status checker — reachable from nothing. It is directly useful for the "agent did something destructive" case. Caveat found while verifying: **its hook contract is stale.** It emits `{matcher, hook}` and reads `process.env.TOOL_NAME`/`TOOL_INPUT`, whereas Claude Code today uses `{matcher, hooks:[{type:"command",command}]}` and passes the payload as **JSON on stdin**. Wiring it up means fixing that contract and pinning it with a test. **Fix:** repair the contract, register install/uninstall/status commands, extract the inlined hook one-liner into a testable module.

**B6 — LOW: unregistered commands and version drift.** `commands/status.ts` and `commands/test.ts` are never imported by `index.ts`. Versions disagree: root `package.json` 1.1.0, cli 1.4.2, README "v1.4.0", deck "v1.3.1".

**B7 — Test coverage is ~5% of surface.** 41 test cases across 9 files. **All 9 commands, all 10 rule packs, and all 5 reporters have zero tests.** CI itself is fine (lint, typecheck, TS tests, Go tests on both Linux and macOS) — there's just almost nothing in it. Priority order: the Seatbelt profile compiler (H4, highest risk), then the rule packs (B2 is exactly the bug a rule-pack test catches), then the commands, then the reporters. `corpus/vulnerable-configs.ts` (966 lines, currently unreachable) should back the rule-pack tests instead of being deleted.

---

## Part 4 — Sequencing

| # | Work | Why first | Est. |
|---|---|---|---|
| 1 | **H1** — fix `setsid` teardown escape | Critical; breaks a guarantee we advertise | 3d |
| 2 | **B1, B2** — honesty + the read-scope false negative | Cheap, credibility-critical | 3d |
| 3 | **H2, H3** — resource limits, tighter exec roots | Closes the rest of the verified sandbox gaps | 6d |
| 4 | **H4** — envelope → real path scoping | Makes `run` usable for real work; feasibility proven | 2w |
| 5 | **B3, B4, B6** — dead flags, reporter dedupe, versions | Hygiene, unblocks trustworthy output | 1w |
| 6 | **H5** — egress brokering | Completes the envelope's network half | 2w |
| 7 | **B5** — wire the runtime policy engine | Mostly revival, not new code | 1w |
| 8 | **H7** — Linux Landlock parity | Broadens the platform story | 3-4w |

**B7 (tests) runs alongside every item**, not as a phase. Every verified attack in Part 1 — including the `osascript` non-escape and the `setsid` escape — becomes a committed regression test. The spike profiles from H4 become the fixtures.

---

## Part 5 — Open items

- **4 of 5 audit surfaces are still unrun.** A parallel bug hunt across `scan`, `check`/taint, `inspect-mcp`/`install`, and `watch`/release-quality was launched; only the sandbox surface had returned when this was written, and an earlier pass over the same surfaces was lost to a session limit. Expect additional findings — in particular, taint-analysis false negatives (which evasions defeat it: intermediate variables, object fields, f-strings, cross-function flows) and whether the published `dist/index.js` resolves tree-sitter native modules correctly from an arbitrary cwd. Re-run before treating this backlog as complete.
- **Fork bomb untested by choice** — it would destabilize the host. Test in a VM before claiming H2 is done.
- **`sandbox-exec` is nominally deprecated.** It still underpins macOS and is what Chrome and others rely on. Accept the risk, but keep the profile generation behind an interface so a future Endpoint Security replacement is contained.
