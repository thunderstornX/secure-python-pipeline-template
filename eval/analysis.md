# Evaluation Analysis

## Corpus

Five widely-used OSS Python projects evaluated against the four-gate pipeline
at a pinned release tag for reproducibility. All evaluations performed
**2026-05-02** with `bandit==1.8.6`, `pip-audit==2.10.0`, `semgrep==1.161.0`.

| Project  | Stars (approx.) | Domain          | Tag      |
|----------|-----------------|-----------------|----------|
| httpie   | 32 k            | CLI HTTP client | 3.2.4    |
| rich     | 49 k            | Terminal UI     | v13.9.4  |
| fastapi  | 78 k            | Web framework   | 0.115.6  |
| black    | 38 k            | Code formatter  | 24.10.0  |
| ruff     | 33 k            | Linter          | 0.8.4    |

## Gate Results (Reproducible)

| Project | Bandit (med/high) | pip-audit | Semgrep | Trufflehog | Overall |
|---------|-------------------|-----------|---------|------------|---------|
| httpie  | 0 (PASS)          | 0 (PASS)  | 1 (FAIL) | 0 (PASS)   | **FAIL** |
| rich    | 0 (PASS)          | 0 (PASS)  | 1 (FAIL) | 0 (PASS)   | **FAIL** |
| fastapi | 0 (PASS)          | 0 (PASS)  | 12 (FAIL)| 0 (PASS)   | **FAIL** |
| black   | 0 (PASS)          | 0 (PASS)  | 12 (FAIL)| 0 (PASS)   | **FAIL** |
| ruff    | 0 (PASS)          | 0 (PASS)  | 4 (FAIL) | 0 (PASS)   | **FAIL** |

**Headline:** all five projects pass the dependency-CVE and secret-leak gates,
but every project triggers at least one Semgrep finding under the combined
`p/python` + project-local ruleset. This **does not mean** any of the
projects is exploitable in production -- it means the pipeline is
sufficiently sensitive that human triage is mandatory before merge.

## Per-Project Findings

### httpie 3.2.4 — 1 Semgrep finding
- `python.lang.security.audit.insecure-transport.requests.request-session-with-http`
  — an `http://` (not `https://`) URL is constructed inside the test
  suite when validating the `--check-status` exit-code logic. False
  positive in test scope; mitigation: add `paths.exclude: ["**/tests/**"]`
  to that specific rule, or annotate the line with `# nosem`.

### rich v13.9.4 — 1 Semgrep finding
- `ali-insecure-deserialisation` (CWE-502) at `rich/style.py:475` — calls
  `marshal.loads()` on `self._meta`, which is set internally by trusted
  callers. Real but **low-priority**: the input is never user-controlled.
  Mitigation: replace `marshal` with `json` or annotate the call site.

### fastapi 0.115.6 — 12 Semgrep findings
- 11x `python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret`
  — hardcoded JWT secrets inside `tests/` files. False positives by
  intent; mitigation: rule path-exclude `**/tests/**`.
- 1x `python.flask.security.audit.directly-returned-format-string`
  — Flask demonstration code in `docs/`. Documentation, not production.

### black 24.10.0 — 12 Semgrep findings
- 4x `python.lang.security.audit.dangerous-subprocess-use-tainted-env-args`
  — `subprocess` calls passing environment-derived arguments. Black
  spawns child processes for autoformatting; the inputs are
  developer-controlled file paths, so this is acceptable in context.
- 4x `ali-dynamic-code-evaluation` — `compile(..., "exec")` used by
  black's own AST round-trip logic (it must `compile` Python source to
  test whether reformatting changed semantics). Inherent to the tool.
- 3x `ali-insecure-deserialisation` — internal pickle use in caching.
  Cache files are written by the same process; not attacker-controlled.
- 1x `subprocess-shell-true` — single legacy call site in tests.

### ruff 0.8.4 — 4 Semgrep findings
- 3x `dangerous-subprocess-use-tainted-env-args` — same pattern as
  black: child-process spawning for testing.
- 1x `ali-dynamic-code-evaluation` — `eval()` in a fixture.

## Discussion

The most striking observation is that the dependency-CVE (`pip-audit`) and
secret-leak (`Trufflehog --only-verified`) gates pass cleanly on every
project, while SAST (`Semgrep`) flags issues in every project. This is the
expected behaviour of a layered pipeline: low-noise gates establish a
hygiene floor; the SAST gate produces signal that requires triage.

A naive interpretation that "0/5 projects pass therefore all are insecure"
is wrong. The correct read is:
1. Dependency hygiene is excellent across the corpus.
2. No project leaks live credentials.
3. Every mature codebase contains AST patterns that warrant a security
   review, even when the reviewer's conclusion is "intentional and safe."
4. A pipeline that *did not* surface findings on these projects would be
   dangerously under-tuned -- evidence that path-exclusions are too
   aggressive or rule patterns are too loose.

## Reproducibility

```bash
# Clone + run all four gates against pinned tags
python eval/run_eval.py

# Re-use existing clones (faster, idempotent)
python eval/run_eval.py --no-clone

# Outputs:
#   eval/cloned_repos/<project>/        -- shallow clones at pinned tags
#   eval/cloned_repos/<project>/.bandit-eval.json   -- per-project bandit JSON
#   eval/results.csv                     -- this table, machine-readable
```

The harness records the date of every run in its console output and
embeds the date used for the Trufflehog snapshot in `run_eval.py:SNAPSHOT_DATE`.
Bandit, pip-audit, and Semgrep are run **live** on every invocation; only
Trufflehog (which requires the binary, not pip-installable) falls back to
a dated snapshot when the binary is absent.

## Threats to Validity

- **Pinned tags may not reflect HEAD.** Findings may already be fixed
  upstream; we evaluate the released artifact, not the development branch.
- **Five projects is a small corpus.** Selection biased toward
  well-maintained projects; less-reviewed code likely surfaces more
  findings.
- **Tool-version sensitivity.** Semgrep's community rule packs evolve;
  results may differ under different Semgrep versions. We pin
  `semgrep==1.161.0` for reproducibility.
- **Trufflehog snapshot.** Refreshed manually on `SNAPSHOT_DATE`; live
  results may diverge if a public secret is rotated or newly leaked.
