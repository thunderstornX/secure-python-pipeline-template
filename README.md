# secure-python-pipeline-template

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.XXXXXXX.svg)](https://doi.org/10.5281/zenodo.XXXXXXX)
[![Security Pipeline](https://github.com/thunderstornX/secure-python-pipeline-template/actions/workflows/security.yml/badge.svg)](https://github.com/thunderstornX/secure-python-pipeline-template/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A composable, four-gate DevSecOps pipeline template for Python projects —
integrating SAST (Semgrep), secret detection (Trufflehog v3), AST analysis
(Bandit), and dependency auditing (pip-audit) into a single reproducible
GitHub Actions workflow.

Described in: *A Composable Four-Gate DevSecOps Pipeline for Python* (see [`paper/paper.pdf`](paper/paper.pdf)).

---

## Gates

| # | Tool | What it catches | Fails pipeline? |
|---|------|-----------------|-----------------|
| 1 | **Semgrep** (SAST) | Injection sinks, insecure deserialization, debug flags, hardcoded secrets | Yes (ERROR rules) |
| 2 | **Trufflehog v3** | Live, verified secrets in git history | Yes |
| 3 | **Bandit** | Python AST: subprocess misuse, weak crypto, SSL bypass | Yes (medium+) |
| 4 | **pip-audit** | CVEs in pinned dependencies (PyPA + OSV) | Yes |

All four gates run in parallel. A summary job posts a gate table to the GitHub Actions job summary.

---

## Quickstart

### 1. Use this template

Click **"Use this template"** on GitHub, or clone manually:

```bash
git clone https://github.com/thunderstornX/secure-python-pipeline-template.git
cd secure-python-pipeline-template
```

### 2. Run the pipeline locally

```bash
./scripts/local_scan.sh              # scan the whole repo
./scripts/local_scan.sh example-project/  # scan just the example app
```

**Real output from `local_scan.sh` on the example-project:**

```
=== Secure Python Pipeline — Local Scan ===
Target : .../example-project
Reports: .../scan-reports

Gate 1: SAST (Semgrep)
[PASS] Semgrep: no findings

Gate 2: Secrets (Trufflehog v3)
[PASS] Trufflehog: no verified secrets

Gate 3: Python Security (Bandit)
[main]  INFO  running on Python 3.10.12
Test results:
    No issues identified.
Code scanned:
    Total lines of code: 203
[PASS] Bandit: no medium/high issues

Gate 4: Dependencies (pip-audit)
No known vulnerabilities found
[PASS] pip-audit: no known CVEs

=== Pipeline Summary ===
All gates passed. Ready to push.
```

### 3. Run the example-project tests

```bash
cd example-project
python -m pytest tests/ -v
```

**Real output:**

```
tests/test_items.py::test_create_item_returns_201 PASSED              [  5%]
tests/test_items.py::test_create_item_unknown_owner_returns_404 PASSED [ 11%]
tests/test_items.py::test_get_item PASSED                             [ 17%]
tests/test_items.py::test_delete_item PASSED                          [ 23%]
tests/test_items.py::test_item_price_validation PASSED                [ 29%]
tests/test_items.py::test_list_items PASSED                           [ 35%]
tests/test_users.py::test_create_user_returns_201 PASSED              [ 41%]
tests/test_users.py::test_create_user_duplicate_returns_409 PASSED    [ 47%]
tests/test_users.py::test_get_user_by_id PASSED                       [ 52%]
tests/test_users.py::test_get_nonexistent_user_returns_404 PASSED     [ 58%]
tests/test_users.py::test_list_users PASSED                           [ 64%]
tests/test_users.py::test_password_validation[short-422] PASSED       [ 70%]
tests/test_users.py::test_password_validation[alllowercase1-422] PASSED [ 76%]
tests/test_users.py::test_password_validation[NOLOWER1NUMBER-201] PASSED [ 82%]
tests/test_users.py::test_password_validation[NoDigitAtAll!!-422] PASSED [ 88%]
tests/test_users.py::test_password_validation[Str0ngPass99!-201] PASSED [ 94%]
tests/test_users.py::test_sql_injection_in_username_is_sanitised PASSED [100%]

17 passed in 3.59s
```

---

## Repository layout

```
.
├── .github/
│   └── workflows/
│       ├── security.yml      # 4-gate pipeline (full scan, weekly cron)
│       └── pr-check.yml      # lightweight PR gate (Bandit + pip-audit, diff only)
├── .semgrep/
│   └── rules.yml             # 8 custom CWE-mapped rules (OWASP Top 10)
├── .trufflehog/
│   └── config.yml            # exclude test fixtures and vendored clones
├── bandit.yml                # Bandit configuration (medium+ threshold)
├── scripts/
│   └── local_scan.sh         # run all 4 gates locally with colour output
├── example-project/          # reference FastAPI app demonstrating mitigations
│   ├── app/
│   │   ├── main.py           # lifespan startup, router registration
│   │   ├── config.py         # pydantic-settings: all secrets from env vars
│   │   ├── database.py       # SQLite WAL mode, parameterised queries only
│   │   ├── models.py         # Pydantic input validation + bcrypt hashing
│   │   └── routes/
│   │       ├── users.py      # CRUD: bcrypt, parameterised SQL, 409 dedup
│   │       └── items.py      # CRUD: foreign-key constraint, price validation
│   └── tests/                # 17 tests covering happy paths + adversarial inputs
├── eval/
│   ├── run_eval.py           # harness: Bandit + pip-audit across 5 OSS projects
│   ├── results.csv           # pre-computed gate results
│   └── analysis.md           # findings discussion
└── paper/
    ├── paper.tex             # IEEE two-column, 4 pages
    └── paper.pdf
```

---

## Custom Semgrep Rules

Eight project-local rules in `.semgrep/rules.yml`, all CWE-mapped:

| Rule | CWE | Severity |
|------|-----|----------|
| `ali-hardcoded-secret-assignment` | CWE-798 | ERROR |
| `ali-sql-injection-f-string` | CWE-89 | ERROR |
| `ali-insecure-deserialisation` | CWE-502 | ERROR |
| `ali-web-framework-debug-enabled` | CWE-489 | ERROR |
| `ali-weak-password-hash` | CWE-327 | ERROR |
| `ali-ssrf-fstring-in-url` | CWE-918 | WARNING |
| `ali-command-injection` | CWE-78 | ERROR |
| `ali-dynamic-code-evaluation` | CWE-95 | ERROR |

---

## Empirical Evaluation

The pipeline was evaluated against 5 OSS Python projects at pinned release tags.

| Project | Stars | Bandit | pip-audit | Semgrep | Trufflehog | Overall |
|---------|-------|--------|-----------|---------|------------|---------|
| httpie 3.2.4 | 32k | FAIL | PASS | FAIL | PASS | **FAIL** |
| rich 13.9.4 | 49k | PASS | PASS | PASS | PASS | **PASS** |
| fastapi 0.115.6 | 78k | PASS | PASS | FAIL | PASS | **FAIL** |
| black 24.10.0 | 38k | PASS | PASS | PASS | PASS | **PASS** |
| ruff 0.8.4 | 33k | PASS | PASS | PASS | PASS | **PASS** |

3/5 projects pass all four gates. See [`eval/analysis.md`](eval/analysis.md) for full findings.

Re-run the evaluation:

```bash
python eval/run_eval.py --no-clone   # use existing clones
python eval/run_eval.py              # re-clone at pinned tags (needs network)
```

---

## Prerequisites

| Gate | Install |
|------|---------|
| Semgrep | `pip install semgrep` |
| Trufflehog v3 | `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \| sh -s -- -b /usr/local/bin` |
| Bandit | `pip install bandit==1.8.6` |
| pip-audit | `pip install pip-audit==2.7.3` |

Or install all at once:

```bash
pip install -r requirements.txt
```

---

## Citing this work

```bibtex
@software{bhutto2025securepipeline,
  author    = {Bhutto, Ali Murtaza},
  title     = {secure-python-pipeline-template},
  year      = {2025},
  doi       = {10.5281/zenodo.XXXXXXX},
  url       = {https://github.com/thunderstornX/secure-python-pipeline-template},
  orcid     = {0009-0007-2787-943X}
}
```

Related research:
- [OSINT Tools Framework](https://doi.org/10.5281/zenodo.16921792)
- [Legal Framework for OSINT](https://doi.org/10.5281/zenodo.16924934)
- [Meshtastic Security Analysis](https://doi.org/10.5281/zenodo.16925037)

---

## License

MIT © 2025 Ali Murtaza Bhutto
