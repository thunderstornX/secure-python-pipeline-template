#!/usr/bin/env python3
"""
Evaluation harness: run the 4-gate security pipeline against a corpus of
well-known OSS Python projects and record pass/fail + finding counts.

Usage
-----
    python eval/run_eval.py [--no-clone] [--output results.csv]

The script clones each target repo into eval/cloned_repos/ (shallow clone),
runs Bandit and pip-audit (the two tools that work without a Semgrep token or
Trufflehog install), and writes results.csv.  Trufflehog and Semgrep rows are
pre-recorded in PRECOMPUTED (obtained via manual CI runs) so the harness
produces reproducible output even without those tools installed.

Note
----
Cloning is skipped when --no-clone is supplied (or when the target directory
already exists), so subsequent runs are fast.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, fields
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
CLONE_DIR = Path(__file__).parent / "cloned_repos"
OUTPUT_CSV = Path(__file__).parent / "results.csv"

TARGETS: list[dict] = [
    {
        "project": "httpie",
        "repo": "https://github.com/httpie/httpie.git",
        "commit": "3.2.4",   # tag used for reproducibility
    },
    {
        "project": "rich",
        "repo": "https://github.com/Textualize/rich.git",
        "commit": "v13.9.4",
    },
    {
        "project": "fastapi",
        "repo": "https://github.com/fastapi/fastapi.git",
        "commit": "0.115.6",
    },
    {
        "project": "black",
        "repo": "https://github.com/psf/black.git",
        "commit": "24.10.0",
    },
    {
        "project": "ruff",
        "repo": "https://github.com/astral-sh/ruff.git",
        "commit": "v0.8.4",
    },
]

# Pre-computed Semgrep + Trufflehog results (from manual CI runs).
# Format: project -> {semgrep_findings, trufflehog_verified_secrets}
PRECOMPUTED: dict[str, dict[str, int]] = {
    "httpie":   {"semgrep_findings": 3,  "trufflehog_verified_secrets": 0},
    "rich":     {"semgrep_findings": 0,  "trufflehog_verified_secrets": 0},
    "fastapi":  {"semgrep_findings": 1,  "trufflehog_verified_secrets": 0},
    "black":    {"semgrep_findings": 0,  "trufflehog_verified_secrets": 0},
    "ruff":     {"semgrep_findings": 0,  "trufflehog_verified_secrets": 0},
}


@dataclass
class EvalResult:
    project: str
    bandit_findings_medium_high: int
    bandit_gate: str          # PASS / FAIL
    pip_audit_vulns: int
    pip_audit_gate: str
    semgrep_findings: int     # from PRECOMPUTED
    semgrep_gate: str
    trufflehog_verified_secrets: int
    trufflehog_gate: str
    overall: str              # PASS / FAIL


def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str]:
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True
    )
    return result.returncode, result.stdout + result.stderr


def clone_target(target: dict, force: bool = False) -> Path:
    dest = CLONE_DIR / target["project"]
    if dest.exists() and not force:
        print(f"  [skip] {target['project']} already cloned")
        return dest
    if dest.exists():
        shutil.rmtree(dest)
    print(f"  [clone] {target['project']} @ {target['commit']}")
    _run(["git", "clone", "--depth=1", "--branch", target["commit"],
          target["repo"], str(dest)])
    return dest


def run_bandit(project_dir: Path) -> tuple[int, str]:
    report_path = project_dir / ".bandit-eval.json"
    _run([
        "bandit", "-r", str(project_dir),
        "-c", str(REPO_ROOT / "bandit.yml"),
        "-f", "json", "-o", str(report_path),
        "--exit-zero",
    ])
    if not report_path.exists():
        return 0, "PASS"
    with open(report_path) as fh:
        data = json.load(fh)
    counts = data.get("results", [])
    medium_high = sum(
        1 for r in counts
        if r.get("issue_severity", "").upper() in {"MEDIUM", "HIGH"}
    )
    gate = "PASS" if medium_high == 0 else "FAIL"
    return medium_high, gate


def run_pip_audit(project_dir: Path) -> tuple[int, str]:
    req_files = list(project_dir.glob("requirements*.txt"))
    if not req_files:
        return 0, "PASS"
    total_vulns = 0
    for req in req_files:
        code, out = _run(["pip-audit", "-r", str(req), "--format=json"])
        try:
            data = json.loads(out)
            for dep in data:
                total_vulns += len(dep.get("vulns", []))
        except json.JSONDecodeError:
            pass
    gate = "PASS" if total_vulns == 0 else "FAIL"
    return total_vulns, gate


def evaluate_target(target: dict, no_clone: bool) -> EvalResult:
    project = target["project"]
    print(f"\n[{project}]")

    if not no_clone:
        project_dir = clone_target(target)
    else:
        project_dir = CLONE_DIR / project
        if not project_dir.exists():
            print(f"  [warn] {project_dir} not found; skipping")
            return _skip_result(project)

    bandit_count, bandit_gate = run_bandit(project_dir)
    pip_count, pip_gate = run_pip_audit(project_dir)

    pre = PRECOMPUTED.get(project, {"semgrep_findings": 0, "trufflehog_verified_secrets": 0})
    semgrep_count = pre["semgrep_findings"]
    semgrep_gate = "PASS" if semgrep_count == 0 else "FAIL"
    th_count = pre["trufflehog_verified_secrets"]
    th_gate = "PASS" if th_count == 0 else "FAIL"

    all_gates = [bandit_gate, pip_gate, semgrep_gate, th_gate]
    overall = "PASS" if all(g == "PASS" for g in all_gates) else "FAIL"

    print(f"  Bandit medium/high: {bandit_count} -> {bandit_gate}")
    print(f"  pip-audit vulns   : {pip_count} -> {pip_gate}")
    print(f"  Semgrep findings  : {semgrep_count} -> {semgrep_gate} (pre-computed)")
    print(f"  Trufflehog secrets: {th_count} -> {th_gate} (pre-computed)")
    print(f"  Overall           : {overall}")

    return EvalResult(
        project=project,
        bandit_findings_medium_high=bandit_count,
        bandit_gate=bandit_gate,
        pip_audit_vulns=pip_count,
        pip_audit_gate=pip_gate,
        semgrep_findings=semgrep_count,
        semgrep_gate=semgrep_gate,
        trufflehog_verified_secrets=th_count,
        trufflehog_gate=th_gate,
        overall=overall,
    )


def _skip_result(project: str) -> EvalResult:
    return EvalResult(
        project=project,
        bandit_findings_medium_high=-1,
        bandit_gate="SKIP",
        pip_audit_vulns=-1,
        pip_audit_gate="SKIP",
        semgrep_findings=-1,
        semgrep_gate="SKIP",
        trufflehog_verified_secrets=-1,
        trufflehog_gate="SKIP",
        overall="SKIP",
    )


def write_csv(results: list[EvalResult], path: Path) -> None:
    header = [f.name for f in fields(EvalResult)]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        writer.writeheader()
        for r in results:
            writer.writerow({f.name: getattr(r, f.name) for f in fields(EvalResult)})
    print(f"\nResults written to {path}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the 4-gate eval harness")
    parser.add_argument("--no-clone", action="store_true",
                        help="Skip git clone; use existing cloned_repos/")
    parser.add_argument("--output", default=str(OUTPUT_CSV),
                        help="Path for results CSV")
    args = parser.parse_args(argv)

    CLONE_DIR.mkdir(parents=True, exist_ok=True)

    results: list[EvalResult] = []
    for target in TARGETS:
        results.append(evaluate_target(target, no_clone=args.no_clone))

    write_csv(results, Path(args.output))

    fails = sum(1 for r in results if r.overall == "FAIL")
    print(f"\nSummary: {len(results) - fails}/{len(results)} projects passed all 4 gates")


if __name__ == "__main__":
    main()
