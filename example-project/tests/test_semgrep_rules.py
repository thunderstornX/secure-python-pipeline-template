"""
Self-test for the eight custom Semgrep rules in `.semgrep/rules.yml`.

Asserts that every rule fires at least once on `eval/semgrep_corpus.py`.

This catches the regression where a rule's pattern syntax silently breaks
(e.g., a typo in `pattern-either:` results in zero matches forever).

Skipped if the `semgrep` binary is not on PATH.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES = REPO_ROOT / ".semgrep" / "rules.yml"
CORPUS = REPO_ROOT / "eval" / "semgrep_corpus.py"

EXPECTED_RULE_SUFFIXES = {
    "ali-hardcoded-secret-assignment",
    "ali-sql-injection-string-build",
    "ali-insecure-deserialisation",
    "ali-web-framework-debug-enabled",
    "ali-weak-password-hash",
    "ali-ssrf-fstring-in-url",
    "ali-command-injection",
    "ali-dynamic-code-evaluation",
}


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_every_rule_fires_on_corpus() -> None:
    """Each of the eight custom rules must produce at least one finding
    on `eval/semgrep_corpus.py`. If a rule's pattern syntax silently
    breaks (e.g., a typo in `pattern-either:`), this test catches it."""
    proc = subprocess.run(
        [
            "semgrep", "scan",
            "--config", str(RULES),
            "--json", "--metrics=off",
            str(CORPUS),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO_ROOT),
    )
    assert proc.stdout, f"semgrep produced no JSON output\nstderr: {proc.stderr}"
    data = json.loads(proc.stdout)
    # Semgrep's check_id is path-derived; we match by trailing suffix so
    # the test is independent of where the rules file lives on disk.
    triggered = {r["check_id"].rsplit(".", 1)[-1] for r in data["results"]}
    missing = EXPECTED_RULE_SUFFIXES - triggered
    assert not missing, f"rules failed to fire on corpus: {sorted(missing)}"
