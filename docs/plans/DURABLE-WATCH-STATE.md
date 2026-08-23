# Durable watch state — design

Status: **proposed** · Scope: the four remaining `watch` findings from the v1.6.0 audit

## Why this needs a design rather than four patches

The audit left four `watch` items unfixed:

| # | Finding | Severity |
|---|---|---|
| 1 | Debounce starvation — a process writing faster than `--debounce` suppresses rescans indefinitely | high |
| 2 | Symlink swap of the watched path permanently blinds the watcher | high |
| 3 | Drift is diffed on finding fingerprints only, never on config content | medium |
| 4 | The baseline is in-memory only — restarting silently adopts a compromised config as "normal" | medium |

They look independent but share one root cause: **the watcher has no durable notion of what it is watching or what "normal" looked like.** Patching them separately produces four half-measures — for example, detecting a symlink swap is useless if the process restart that follows re-baselines against the swapped target anyway.

## Decisions

### 1. Storage: a JSON file per target, written atomically

**Decision: plain JSON, one file per watched target, `write-temp + rename`. No embedded database.**

The open question proposed SQLite or LMDB for "high-frequency writes". Measured against actual behaviour, that framing does not hold:

- State is written **once per drift event**, and drift events are already debounced. The realistic write rate is single-digit writes per minute, with a pathological ceiling of a few per second. A whole baseline is a few KB.
- More decisively: SQLite and LMDB are **native modules**. This audit spent most of its effort on native-module packaging failures in this exact CLI — a tree-sitter ABI mismatch, a single-architecture sandbox binary shipped to every platform, and an `ERESOLVE` conflict that broke `npm install` inside the published package. Adding a third native dependency to fix a few-KB-per-minute write directly worsens the problem class we just finished fixing, for no measurable gain.

Atomicity comes from `fs.writeFileSync(tmp)` followed by `fs.renameSync(tmp, final)`, which is atomic within a filesystem. That is sufficient: a torn write is the only corruption risk, and rename eliminates it. A corrupt or unreadable state file is treated as "no baseline" and re-established — never as "no drift".

**Layout.** State is keyed by target, which also fixes an existing bug: `~/.wh-agent/state.json` is a single un-keyed global file today, so scanning a second target makes the next scan of the first report spurious drift.

```
~/.wh-agent/baselines/<sha256(resolve(target))[0:16]>.json
```

The key is the **logical path the user asked to watch** (absolute, but *not* symlink-resolved); the resolved identity is stored inside the file.

Keying by realpath instead is tempting and wrong — verified by testing during implementation. A symlink swap would then produce a *different* key, so the swapped target quietly gets a fresh baseline and the swap, the thing we most want to catch, becomes invisible. The logical path is the stable identity; what it resolves to is exactly what can change and must be compared.

File mode `0600`, directory `0700`. The baseline records what a user's agent configuration looks like, including finding locations; it is not secret, but it is not other users' business either.

### 2. Fingerprinting: reuse the existing hash, and add a content digest

**Decision: keep `sha256(id:file:line:severity)` for findings; add `sha256` per config file.**

`hashFinding` already exists and is adequate — sha256 truncation is not a collision concern at these cardinalities (tens to low thousands of findings), and changing the algorithm would invalidate every stored baseline for no benefit.

The real gap is *what* is fingerprinted. Diffing findings alone means a change that produces an identical finding set registers as no drift at all — swapping an MCP server's package for a malicious one with the same permissions shape is invisible. So the baseline stores **both**:

```jsonc
{
  "findingIds":  { "<sha256>": { "id": "...", "file": "...", "severity": "..." } },
  "fileDigests": { "<relative path>": "<sha256 of contents>" }
}
```

Drift is then the union of: findings appearing, findings disappearing, **and** a tracked file's content digest changing. The third class is reported distinctly ("configuration changed with no change in findings"), because it is a weaker signal than a new finding and should not be presented as one.

### 3. Symlink swaps: track filesystem identity, not just paths

**Decision: record `(dev, ino, realpath)` for the watch root and every tracked file.**

A path is not an identity. `fs.watch` holds a descriptor to whatever the path resolved to at start; replacing the directory with a symlink elsewhere leaves the watcher watching a detached inode — no events, no error, and it still reports itself as running.

Each rescan compares the stored identity against the current one and treats a mismatch as drift of its own kind:

- **root realpath changed** → the watched directory was replaced. Critical: re-establish watchers against the new target and alert.
- **file `dev`/`ino` changed but path is the same** → replaced rather than edited. Normal for atomic-rename editors (vim, VS Code), so this is *not* an alert by itself — it is a signal to re-read and re-digest the file, and only the resulting content or finding change is reported.

That distinction matters: treating every inode change as an attack would fire on every save in a normal editor, and an alert that fires constantly is an alert nobody reads.

### 4. Debounce starvation: bound the wait

**Decision: debounce with a maximum delay (`maxWait = max(5 × debounceMs, 5000ms)`).**

The current debounce restarts its timer on every event, so a process writing faster than the interval postpones the rescan forever — trivially weaponisable, and also reachable by accident with a noisy build watcher. Standard fix: alongside the trailing debounce timer, track the timestamp of the first event in the burst and force a rescan once `maxWait` elapses regardless of continuing activity.

Rescans remain serialised, as they already are; `maxWait` only guarantees that a rescan *starts*.

## What this deliberately does not do

- No migration of the existing `~/.wh-agent/state.json`. It is an un-keyed global used by `scan --watchdog`; the new per-target files live beside it under `baselines/`, and the old file keeps working for the scan path.
- No cross-machine or shared state. Out of scope.
- No baseline signing. Tamper-evidence for the state file is worth discussing, but an attacker who can write to `~/.wh-agent/` can generally also edit the configs being watched, so it does not close a meaningful gap on its own.

## Verification

1. Restart the watcher after a drift event — the stored baseline is reloaded and the already-known finding is *not* re-reported as new.
2. Start a watcher, replace the watched directory with a symlink to a different tree, touch a file — the root-identity change is detected and alerted.
3. Write to the watched directory in a tight loop faster than `--debounce` — a rescan still occurs within `maxWait`.
4. Change an MCP server's package to a different one with an identical permissions shape — content-digest drift is reported even though the finding set is unchanged.
5. Corrupt the state file (truncate it mid-JSON) — the watcher re-establishes a baseline and says so, rather than reporting "no drift".
