# Static-surface bug hunt — verified findings (Step A)

> ## ✅ RESOLVED THIS SESSION (fail-closed correctness + detection wins)
> - **check #1 — fail-OPEN on analysis error**: now emits an `analysis-error` finding in
>   EVERY format, marks the file `analysis_failed`, and exits **2** (fail closed). Regression
>   test in `e2e-fixes.test.ts`.
> - **scan #1 — malformed JSON silently passed**: `runParseabilityChecks` emits a **critical**
>   `config-unparseable` finding (so the CI gate fails) instead of grading it clean.
> - **scan #5 — 0-file guard bypassed by machine formats**: guard moved BEFORE the format
>   dispatch; machine formats now emit the warning on stderr + exit **1** (no false green).
> - **scan #3 — score averaging hid criticals**: overall grade is now **capped by the worst
>   real finding** (any real critical ⇒ ≤ D; any real high ⇒ ≤ C), respecting example
>   down-weighting. (One critical → Grade D, verified.)
> - **scan #4 — hook `curl|bash` RCE**: pipe-to-shell critical now fires for **all** hook
>   events (not just SessionStart), and the narrow curl regex was loosened so `-s`/flags no
>   longer evade it. Referenced hook *scripts* are also covered by the B2 packs.
> - **scan #2 (partial) — skill/hook bundled scripts never analyzed**: B2 packs now scan
>   bundled script bodies (reverse shells / injection / sensitive-paths). Taint-in-scan (env→
>   network flows) remains a follow-up (scan doesn't run the taint engine).
> - **check #3 — `--fix` corrupted Python/Bash**: emits a bare `""` for `.py/.sh` (no
>   line-ending `#` comment); JS keeps its `/* */` note. Verified: fixed files still parse.
> - **install #1 — never consulted the CVE/malicious DB**: `installAgent` now calls
>   `checkPackageName` early (blocks known-bad names before any fetch, exit 2) and re-checks
>   the resolved version (catches a compromised `latest`), without false-positiving a
>   legitimate package whose latest is clean.
> - **inspect-mcp #2 — narrow injection regex**: broadened the override phrase (catches
>   "ignore ALL previous instructions") and added secrecy + tool-precedence directives.
>
> ## ✅ RESOLVED — round 2 (taint depth + coverage)
> - **`--global` coverage (scan #6)**: added **Codex CLI, Continue, Zed, Cline** to
>   `GLOBAL_AGENTS` (Aider is file-based `~/.aider.conf.yml` — still TODO).
> - **JS/TS taint (check #4/#5)**: fixed the member/field **dead store** (`o.x = secret;
>   fetch(o.x)`), class attributes (`this.x`), and simple sink/source **aliases**
>   (`const r = axios; r.post(…)`, `const e = process.env`). `checkTaintedVars` now looks up
>   member-access paths; `getIdentifierName` handles `this`.
> - **Polyglot taint (check #5/#6)**: Python sinks now match **any receiver** (`s =
>   Session(); s.post`, `import requests as r; r.post`) via bare HTTP-verb method names
>   (excluding `get` to avoid `dict.get`); Rust **chained builder** (`.body(secret).send()`)
>   via `body`/`json`/`form` sinks; Bash **direct secret-named env expansion**
>   (`curl -d "$AWS_SECRET_ACCESS_KEY"`). All verified with no false positives (dict.get,
>   `$USER_NAME`, non-secret `.json()` all correctly not flagged); 10 new taint regression tests.
>
> ## ✅ RESOLVED — round 3 (interprocedural taint)
> - **Interprocedural taint** (check #2 — the biggest remaining false-negative class) via
>   per-function **summaries + a bounded fixpoint**, for **JS/TS, Python, and Rust**
>   (Bash deferred): return-taint (`x = gs()` / `sink(gs())`), parameter pass-through
>   (`sink(ident(secret))`), and parameter-to-sink (`send(secret)`), including n-hop chains.
>   Guardrail: **same-file functions only** — an imported/unknown function is never assumed
>   to taint or sink. Also fixed a latent FP where a user function named `send`/`post`
>   collided with the bare HTTP-verb sinks (now method-only). ~15 new positive+negative
>   regression tests; recursion terminates; existing suites green. See
>   [INTERPROCEDURAL-TAINT-PLAN.md](./INTERPROCEDURAL-TAINT-PLAN.md).
>
> **Remaining (deeper):** deep-nesting **traversal cap** (now fails closed but still can't
> analyze such files), JS array-push taint, Python subscript source-alias
> (`from os import environ as e; e["K"]`), higher-order/callback and cross-file taint,
> taint-in-scan, SARIF rule-metadata quality (scan #7), CVE-DB coverage/honesty (mcp #5),
> `--live` timeout/parse robustness (mcp #6), Aider `~/.aider.conf.yml` discovery, and the
> #8 filesystem-server rating consistency.



Adversarial bug hunt over `scan`, `check`, `inspect-mcp`, `install` (and release/`watch`).
Every item below was **reproduced by running the built CLI** against crafted fixtures.
Ranked within each surface. Prefix `[FN]` = false negative (tool said clean but wasn't),
the worst class for a security scanner.

## `check` / taint (highest-impact)
1. **[FN] Fail-OPEN on analysis error (CRITICAL).** Deeply-nested input (~1000 nested
   parens) overflows the recursive walkers; in `--format json`/`sarif` the error is
   swallowed (`check.ts:114-118` only logs in text mode) → `findings: []`, **exit 0**,
   `json-v2` even says `status:"scanned_full"`. A scanner that crashes must fail *closed*.
   Fix: emit an `analysis_error` finding + non-zero exit in all formats; cap traversal depth.
2. **[FN] Interprocedural blindness (HIGH→CRITICAL).** Both analyzers are intraprocedural:
   `def get_secret(): return os.getenv(...)` then `requests.post(..., get_secret())` is
   MISSED in every language (inline is caught). Fix: per-function return-taint summaries.
3. **`--fix` corrupts Python/Bash files (HIGH).** The stub adds a trailing `#` comment
   inline, commenting out the rest of the line → `SyntaxError` (`remediator.ts:36-41`). JS
   is safe (`/* */`). Fix: for `.py/.sh` emit `""` with no inline `#`, or a preceding line.
4. **[FN] JS member/field taint is a dead store (HIGH).** `o.x=secret; fetch(...,o.x)`,
   `this.x=...`, `arr.push(secret)` all MISSED — `handleAssignment` writes dotted keys but
   `checkTaintedVars`/`findSource` only look up bare identifiers (`analyzer.ts:342,292`).
   Python catches the equivalent (over-taints container). Fix: track member-access paths.
5. **[FN] Import/alias & receiver evasion (HIGH).** `import requests as r; r.post(...)`,
   `const r=axios; r.post(...)`, `s=requests.Session(); s.post(...)` all MISSED (sink match
   is literal-name/fixed-receiver). Fix: resolve aliases; match by method name on any receiver.
6. **[FN] Rust idiomatic exfil missed (HIGH).** `client.post(url).body(secret).send()` —
   `.body()` isn't a sink and `.post()/.send()` carry no tainted arg (`polyglot.ts:327-335`).
   Fix: treat `.body()/.json()/.form()/.query()` as taint-carrying into the request chain.
7. **[FN] Bash direct-env exfil missed (MED).** `curl -d "$AWS_SECRET_ACCESS_KEY"` with no
   `cat`/`printenv` intermediate. 8. **Golden-snapshot fingerprint (LOW):** unknown ext
   (`.rb/.go`) falls back to raw-text hash → comment edits spuriously change it (namespaced
   `sha256-text:`, so not a security FN — a drift-noise/UX issue). Consider fail-closed.

## `scan`
1. **[FN] Malformed JSON config → 0 findings, Grade A, "passed" (CRITICAL).** Every rule
   `catch{return []}` on parse failure and nothing emits an "unparseable config" finding —
   an unreadable security config is graded a perfect 100. Fix: emit a high-severity
   "config could not be parsed — not audited" finding.
2. **[FN] Skill-bundled script never security-analyzed (CRITICAL).** A `skills/x/scripts/*.py`
   that reads a secret and POSTs it out is discovered but typed `unknown` (`scanner/discovery.ts
   inferType`), so the behavioral rules skip it and `scan` never runs taint. Fix: classify
   skill/agent bundled scripts as `hook-code`, or run the taint heuristic on `unknown` code.
3. **Score averaging hides criticals (CRITICAL/wrong-output).** `computeScore` averages 5
   category scores, so one critical → Grade **A** (95). Exit code is correctly 2, but the
   number lies (`reporter/score.ts:107-114`). Fix: cap grade by worst severity / use min.
4. **[FN] `curl…|bash` RCE in hooks under-rated (HIGH).** Pipe-to-shell is only CRITICAL for
   `SessionStart`; for Pre/PostToolUse/Stop it's merely "high", and `curl -s …|bash` is missed
   entirely (regex requires `http` immediately after `curl `). Fix: apply pipe-to-shell
   critical to all hook events; allow intervening flags.
5. **[FN] Non-terminal formats bypass the 0-file guard (HIGH).** `scan <empty> --format json`
   → score 100/A/exit 0; the honest "nothing scanned" guard runs only in terminal mode
   (`scan.ts:204-221` exits before it). CI gets a false green. Fix: move guard above dispatch.
6. **`--global` misses 2026 agents (MED).** Codex CLI, Cline, Continue, Zed (global), Aider
   absent from `GLOBAL_AGENTS` (`discovery.ts:21-94`). 7. **SARIF low-quality (LOW):**
   `driver.rules:[]` and per-finding dynamic `ruleId` → GitHub can't group/dedupe.

## `inspect-mcp` / `install`
1. **[FN] `install` never consults its own malicious-package/CVE DB (HIGH).** `install` does
   typosquat + lifecycle + secrets but never calls `cve-database.ts`; a known-compromised
   package (e.g. `intercom-client@7.0.4`, listed at `cve-database.ts:235`) installs clean.
   `inspect-mcp` *does* use the DB. Fix: call `checkPackageName()` in `installAgent` (~3 lines).
2. **[FN] Canonical injection phrase missed (HIGH).** `"ignore all previous instructions"`
   (two words between) and `"disregard previous instructions"` slip past the override regex
   (`mcp-tool-poisoning.ts:163-167`, only one adjective allowed); the `<IMPORTANT>do not tell
   the user…</IMPORTANT>` tool-poisoning sidenote has no pattern. Fix: broaden regex + add
   secrecy/"always call first" directives.
3. **[FN] `git clone <http url>` not flagged (MED/HIGH).** Remote-fetch detection misses `git`
   as a fetch command and non-github `.git` URLs (`mcp.ts:617,931`).
4. **[FN] Trailing-slash bypass (MED).** `/Users/victim/` evades the broad-access regex
   (`$`-anchored, no optional sep) (`mcp-tool-poisoning.ts:123-131`).
5. **CVE DB is decorative/misleading (MED).** 21 detailed CVEs are never consulted by any rule
   (`getCveDatabase`/`lookupCve` have no non-test callers); real detection is 3 server packages
   + 2 campaign lists; no update mechanism. Fix: wire `detectionPatterns` in, or delete + doc.
6. **`--live` robustness (LOW).** `--timeout` has a hidden 5s floor and NaN throws → swallowed
   as "0 tools"; JSON-only parse fails closed on preamble; timeout can orphan the MCP server.

## release / `watch`
1. **[FN] `.mcp.json` (dot-prefixed) is never scanned (HIGH).** The canonical Claude Code
   *project* MCP file — checked into repos, the highest supply-chain-risk MCP surface — is
   absent from discovery's `directFiles` (`scanner/discovery.ts:192-194`) and `inferType`
   (`:315`), so neither `scan` nor `watch` sees it. `mcp.json` (no dot) works. Fix: add
   `.mcp.json`/`.claude/.mcp.json` to `directFiles` and the `mcp-json` classifier. **← fixed this session.**
2. **Single-platform `wh-sandbox` shipped to all platforms (MED).** `prepublishOnly` builds
   one native binary; a non-matching OS/arch gets "Exec format error" from `run`. Capped
   because `run` is `--experimental`/macOS-only. Fix: per-platform optionalDependencies or
   download-on-`setup`.
3. **`status` and `test` command modules exist but aren't registered in `index.ts` (LOW).**
   Dead code / advertised-but-unreachable. Fix: wire them or delete.
4. **`watch` has no `--format json` (LOW).** Inconsistent with `scan`/`check`; no
   machine-readable drift output. Fix: add JSON mode or document the absence.

**Verified SAFE (not bugs):** the published tarball runs standalone (tree-sitter externals
resolve, `popular-packages.json` bundled, `wh-sandbox` path resolves, `--version` correct);
the **webhook does NOT leak secret values** (`alerts.ts:formatWebhookPayload` sends only
`{id,severity,title,file}`, evidence masked at source); `--block` exits 2 correctly; the
watcher survives atomic-rename saves, rapid edits (coalesced), and deletion of watched
files/dir without crashing.

---
### Recommended fix order (safety first, low-risk-first)
1. `check` #1 fail-open + `scan` #1 malformed-JSON + `scan` #5 0-file guard — **fail-closed correctness** (a scanner must never say "clean" when it didn't/couldn't scan).
2. `check` #3 `--fix` corruption — stops us from breaking user files.
3. `install` #1 CVE-DB wiring + `inspect-mcp` #2 injection regex — small, high-signal detection wins.
4. `scan` #2 skill-script taint + #3 score cap + #4 hook-RCE — meaningful detection gaps.
5. Taint depth (`check` #2/#4/#5/#6), coverage (`scan` #6, mcp #3/#4), and polish (SARIF, CVE-DB honesty, `--live`).
