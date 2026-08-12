# Plan — Interprocedural taint (function-summary analysis)

Status: **proposed**. The largest remaining false-negative class in the taint engine.
Both analyzers (`taint/analyzer.ts` for JS/TS via the TypeScript compiler;
`taint/polyglot.ts` for Python/Bash/Rust via tree-sitter) are **intraprocedural** —
they track flow only within a single function body. This plan adds a lightweight,
false-positive-controlled interprocedural layer.

## 1. Objective — the exact gaps to close

All currently MISSED (verified in the bug hunt), across every language:

| Class | Example | Why missed today |
|---|---|---|
| **Return-taint** | `def gs(): return os.getenv("K")` … `requests.post(u, gs())` | `gs()` is a call to a user function, not a known source |
| **Return-taint via var** | `x = gs(); requests.post(u, x)` | same; `x` never becomes tainted |
| **Param-to-sink** | `def send(x): requests.post(u, x)` … `send(secret)` | `send` isn't in the sink list; the sink is *inside* it |
| **Param pass-through** | `def ident(x): return x` … `post(u, ident(secret))` | return isn't connected to the arg |
| **Chains** | `f()` → `g()` → source/sink | no cross-function propagation |

Non-goals for v1 (documented limitations, deferred): higher-order functions /
callbacks passed as values, function references stored in variables/dicts, methods
resolved across files, cross-FILE calls (imports), and Bash functions (interprocedural
taint in shell is low-value and the grammar makes it noisy). These stay intraprocedural.

## 2. Design — per-function summaries + fixpoint

The standard, tractable approach: compute a **summary** for each function we can fully
see (defined in the file), then apply summaries at call sites. Iterate to a fixpoint so
chains and (bounded) recursion resolve.

### 2.1 Summary shape

```
interface FnSummary {
  returnsTaint: SourceKind | null;   // does calling F yield tainted data? ("sensitive" | "input" | null)
  paramReturns: Set<number>;         // params whose taint flows to the RETURN value (pass-through)
  paramSinks: Map<number, SinkKind>; // params whose taint reaches a sink INSIDE F, and which kind
}
```

- `returnsTaint` — F's body returns a value derived from an in-body source, or from a
  parameter recorded in `paramReturns` **when that parameter is passed a tainted arg**
  (that part is resolved at the call site, not baked into `returnsTaint`).
  `returnsTaint` here means: returns taint *unconditionally* (an in-body source reaches
  a return). Parameter-derived returns are handled via `paramReturns`.
- `paramReturns` — indices i such that parameter i flows to a `return`. Enables
  `y = ident(secret)` → y tainted, and `post(u, ident(secret))` → flow.
- `paramSinks` — indices i such that parameter i flows into a network/exec sink in F.
  Enables `send(secret)` → flow (tainted arg reaches a sink through the callee).

### 2.2 Computing a summary (reuse the intraprocedural engine)

Both analyzers already answer, within a body, "does subtree X reach a source?" and
"is variable V tainted given a seed set?". Compute a summary by running that same
machinery over the function body with the **parameters seeded as tainted sources**:

1. Seed each parameter name as a distinct tainted marker `param#i`.
2. Run the existing fixpoint propagation over the body's assignments.
3. `paramSinks`: for each sink call in the body, if a `param#i` marker reaches its
   args → add i (with the sink kind).
4. `paramReturns`: for each `return` expression, collect which `param#i` markers reach
   it → those i.
5. `returnsTaint`: if any `return` expression reaches a real in-body **source**
   (`os.getenv(...)`, `process.env`, a call to another function whose `returnsTaint`
   is set — see fixpoint) → set the kind ("sensitive" dominates "input").

### 2.3 Fixpoint over the call graph

A function may call another before we've summarized it (forward refs, recursion).
Resolve by iterating:

```
summaries = {} for all funcs, initialized empty
repeat up to K rounds (K = min(funcCount + 2, 12)):
  changed = false
  for each function F:
    s = computeSummary(F, using current `summaries` for calls to other funcs)
    if s != summaries[F]: summaries[F] = s; changed = true
  if not changed: break
```

Monotonic (summaries only gain taint), so it converges; the K cap guarantees
termination even on pathological mutual recursion.

### 2.4 Applying summaries (the two new hooks)

During the existing analysis, add:

- **Calls as sources.** When resolving whether a subtree is a source (assignment RHS,
  or a sink argument), a call `F(argExprs)` is a source if:
  - `summaries[F].returnsTaint` is set → that kind; OR
  - some argExpr at position i is tainted AND `i ∈ summaries[F].paramReturns` → that
    arg's kind. (This gives pass-through: `ident(secret)`.)
- **Param-to-sink calls.** Add one pass over ALL call expressions: for a call `F(args)`
  where `summaries[F].paramSinks` is non-empty, if the arg at a `paramSinks` index is
  tainted (a source, or a tainted var) → emit a flow (source = that arg's origin, sink
  = the sink kind recorded in the summary; describe as "via F()").

## 3. Per-language specifics

### 3.1 JS/TS — `taint/analyzer.ts` (TypeScript compiler)

- **Functions:** `ts.isFunctionDeclaration` (has `.name`), `ts.isMethodDeclaration`,
  and `const f = () => …` / `const f = function(){}` (name from the VariableDeclaration).
  Build `functions: Map<string, {params: string[]; body: ts.Node}>`.
- **Params:** `node.parameters.map(p => p.name.getText())`.
- **Returns:** collect `ts.isReturnStatement` expressions in the body (not crossing a
  nested function boundary).
- Reuse `findSource`/`checkTaintedVars` logic, generalized to take a seed set. The
  existing `tainted` map becomes per-scope; seed it with `param#i` for summary
  computation.
- Apply in `findSource` (calls-as-sources), and add a `checkCallParamSinks` pass in
  `visit` alongside the existing sink handling.

### 3.2 Python — `taint/polyglot.ts` (tree-sitter)

- **Functions:** `function_definition` → `name` field, `parameters` (identifiers),
  `body` (`block`). Methods are `function_definition` inside a `class_definition`;
  treat `self`-qualified calls conservatively (v1: match by bare method name, already
  done for sinks).
- **Returns:** `return_statement` nodes within the body.
- Reuse `subtreeSourceKind` / `collectIdentifiers` / the assignment fixpoint, seeding
  parameter names as tainted. `paramSinks`/`paramReturns` computed exactly as §2.2.
- Apply in the assignment fixpoint (a call to F with `returnsTaint`/pass-through taints
  the target) and in the sink pass (add the param-to-sink call pass).

### 3.3 Rust — `taint/polyglot.ts`

- **Functions:** `function_item` → `name`, `parameters` (`parameter` nodes), `block`.
  Rust returns implicitly (final expression) — treat the block's final expression AND
  `return` expressions as returns.
- Same summary machinery. Lower priority than Py/JS but cheap once the framework exists.

### 3.4 Bash — **deferred** (documented). Shell "functions" rarely carry taint in a way
worth the FP risk; keep Bash intraprocedural.

## 4. False-positive control (the make-or-break)

Interprocedural analysis is where FPs multiply. Guardrails:

1. **Same-file, fully-visible functions only.** No summary for imported/unknown
   functions → their calls are treated exactly as today (no assumed taint, no assumed
   sink). This is the single most important rule: never *assume* an unseen function
   taints or sinks.
2. **Monotonic, bounded fixpoint** (K cap) — no runaway.
3. **Conservative return/sink attribution** — a param counts for `paramSinks` only if
   the existing (already FP-tuned) intraprocedural engine says it reaches a sink; reuse,
   don't reinvent, the matching so precision matches the current bar.
4. **No new sink/source *patterns*** — this plan changes *reachability*, not the
   source/sink lists, so it can't introduce a new class of literal FP.
5. **Shadowing/scope**: a parameter named the same as an outer variable must not leak
   its seed outside the function; compute summaries in an isolated seed set per function.
6. **Negative tests are first-class** (see §6): every phase ships with FP fixtures that
   must stay clean.

## 5. Phased implementation (each phase independently shippable + tested)

1. **Framework + JS/TS return-taint** — function collection, summary struct, fixpoint,
   calls-as-sources (returnsTaint + paramReturns). Covers `gs()` and `x = gs()`.
2. **JS/TS param-to-sink** — the `checkCallParamSinks` pass. Covers `send(secret)`.
3. **Python** — port phases 1–2 to the tree-sitter path (share the summary/fixpoint
   code; only the AST accessors differ).
4. **Rust** — same, plus implicit-return handling.
5. **Docs + limitations** — update README/backlog: interprocedural within a file, list
   deferred cases honestly.

Refactor first (small): extract the "seed set → tainted vars / does subtree reach a
source" core in each analyzer into a function that takes an explicit seed set, so both
the top-level pass and summary computation call the same code.

## 6. Test plan (concrete fixtures, per language)

Positive (must be CAUGHT after the relevant phase):
- return-taint: `gs(){return env}` ; `post(u, gs())`
- return-taint via var: `x = gs(); post(u, x)`
- param pass-through: `ident(x){return x}` ; `post(u, ident(secret))`
- param-to-sink: `send(x){post(u,x)}` ; `send(secret)`
- 2-hop chain: `a()` returns `b()` returns source ; sink on `a()`
- param-to-sink 2-hop: `outer(x){ send(x) }` ; `outer(secret)`
- recursion terminates (a function that calls itself) — analysis returns, no hang.

Negative (must stay clean — no false positive):
- `gs(){return "hello"}` ; `post(u, gs())`
- `send(x){print(x)}` ; `send(secret)`  (print is not a sink)
- unknown/imported function: `post(u, external_lib.helper(secret))` → not assumed
  tainted (external not summarized)
- shadowing: an inner param `x` must not taint an unrelated outer `x`
- pass a NON-tainted arg to a paramSink function → no flow

Wire positives/negatives into `analyzer.test.ts` (bun, JS) and `polyglot.nodetest.ts`
(tsx, Py/Rust). Also add one end-to-end `check` fixture per language.

## 7. Risks, limitations, rollback

- **Risk: FP blow-up.** Mitigated by §4 (same-file only, reuse existing matching,
  negative tests). If a phase shows FPs on the negative corpus, it doesn't ship.
- **Risk: performance** on large files (many functions × fixpoint). Mitigate: cap K,
  memoize per-function body analysis, only summarize functions that contain a source,
  a sink, OR a `return` (skip inert ones). Realistic files are small; guard with the
  existing per-file work.
- **Limitation (accepted):** intra-file only; no callbacks/HOFs/stored fn refs; methods
  matched by name not resolved type. Document in README's taint section.
- **Rollback:** the interprocedural layer is additive (new source/sink *reachability*);
  gate it behind the existing `analyzeTaint` entry so it can be disabled by reverting
  the summary application if a regression surfaces post-merge.

## 8. Effort (rough)

- Phase 1 (JS/TS framework + return-taint): the bulk of the design work; moderate.
- Phase 2 (JS/TS param-to-sink): small once the framework exists.
- Phase 3 (Python): moderate (AST accessors + share core).
- Phase 4 (Rust): small.
- Testing throughout (positive + negative corpus): continuous.

Sequence so value lands early: ship Phase 1+2 (JS/TS) first (biggest ecosystem,
cleanest AST via the TS compiler), then Python, then Rust.
