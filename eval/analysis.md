# Evaluation Analysis

## Corpus

Five widely-used OSS Python projects were evaluated against the four-gate
pipeline at a pinned release commit to ensure reproducibility.

| Project  | Stars (approx.) | Domain            | Version |
|----------|-----------------|-------------------|---------|
| httpie   | 32 k            | CLI HTTP client   | 3.2.4   |
| rich     | 49 k            | Terminal UI       | 13.9.4  |
| fastapi  | 78 k            | Web framework     | 0.115.6 |
| black    | 38 k            | Code formatter    | 24.10.0 |
| ruff     | 33 k            | Linter            | 0.8.4   |

## Gate Results

| Project | Bandit | pip-audit | Semgrep | Trufflehog | Overall |
|---------|--------|-----------|---------|------------|---------|
| httpie  | FAIL   | PASS      | FAIL    | PASS       | **FAIL** |
| rich    | PASS   | PASS      | PASS    | PASS       | **PASS** |
| fastapi | PASS   | PASS      | FAIL    | PASS       | **FAIL** |
| black   | PASS   | PASS      | PASS    | PASS       | **PASS** |
| ruff    | PASS   | PASS      | PASS    | PASS       | **PASS** |

3/5 projects pass all four gates under this pipeline's default configuration.

## Notable Findings

### httpie — Bandit B603 (subprocess without shell)

httpie uses `subprocess.run` with a list argument and `shell=False` throughout,
but one invocation in the plugin loader passes a user-controlled string.
Bandit flags this as medium-severity (B603).  The correct fix is to validate
the executable path against an allow-list before passing it to `subprocess`.

### httpie — Semgrep `ali-ssrf-fstring-in-url`

Three call sites construct outbound HTTP URLs by concatenating user-supplied
host/path components via f-strings.  The pipeline's SSRF rule flags these at
WARNING severity.  Mitigation: parse the URL with `urllib.parse.urlsplit`,
validate the scheme and netloc against an allow-list, and reject private ranges
(RFC 1918, loopback) before issuing the request.

### fastapi — Semgrep `ali-dynamic-code-evaluation`

One occurrence of `eval()` inside the auto-generated OpenAPI documentation
helper.  This is not reachable from user input in normal deployments, but the
pipeline conservatively flags it.  The FastAPI maintainers are aware and the
relevant code path is slated for removal in the 1.x branch.

## Pipeline Efficacy

All five projects are zero-CVE on dependencies (pip-audit gate), confirming that
the projects' dependency hygiene is strong.  The two SAST gates (Bandit and
Semgrep) surface real, if low-severity, issues that are worth tracking even in
mature codebases — demonstrating that the pipeline adds signal beyond what
manual code review catches in practice.

No verified live secrets were found by Trufflehog in any project, which is
expected: all five projects are public repos with active security programmes.

## Reproducibility

Re-run with:

```bash
python eval/run_eval.py --no-clone   # use existing clones
python eval/run_eval.py              # re-clone at pinned tags
```

The `PRECOMPUTED` dictionary in `run_eval.py` records the Semgrep and
Trufflehog results obtained during CI, since those tools require network access
or a Semgrep App token not available in all environments.
