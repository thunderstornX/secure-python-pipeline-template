#!/usr/bin/env bash
# Run the full 4-gate security pipeline locally.
#
# Usage:
#   ./scripts/local_scan.sh [TARGET_DIR]
#
# TARGET_DIR defaults to the repo root.  Pass a sub-directory (e.g.
# example-project/) to limit the scan scope during development.
#
# Prerequisites (all pinned in requirements.txt):
#   pip install bandit pip-audit semgrep
#   Install Trufflehog v3 from: https://github.com/trufflesecurity/trufflehog
#
# Exit codes:
#   0  All gates passed
#   1  One or more gates failed (see per-gate output above)

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

pass() { echo -e "${GREEN}[PASS]${RESET} $1"; }
fail() { echo -e "${RED}[FAIL]${RESET} $1"; }
info() { echo -e "${CYAN}[INFO]${RESET} $1"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $1"; }

# ── Config ─────────────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-$REPO_ROOT}"
REPORT_DIR="$REPO_ROOT/.scan-reports"
GATE_FAILURES=0

mkdir -p "$REPORT_DIR"

echo -e "\n${BOLD}=== Secure Python Pipeline — Local Scan ===${RESET}"
echo -e "Target : $TARGET"
echo -e "Reports: $REPORT_DIR\n"

# ── Gate 1: Semgrep (SAST) ─────────────────────────────────────────────────
echo -e "${BOLD}Gate 1: SAST (Semgrep)${RESET}"
if command -v semgrep &>/dev/null; then
    set +e
    semgrep scan \
        --config p/owasp-top-ten \
        --config p/python \
        --config "$REPO_ROOT/.semgrep/rules.yml" \
        --error \
        --json --output="$REPORT_DIR/semgrep-report.json" \
        --metrics=off \
        --exclude="eval/cloned_repos" \
        "$TARGET"
    SEMGREP_EXIT=$?
    set -e
    if [ "$SEMGREP_EXIT" -eq 0 ]; then
        pass "Semgrep: no findings"
    else
        fail "Semgrep: findings detected — see $REPORT_DIR/semgrep-report.json"
        GATE_FAILURES=$((GATE_FAILURES + 1))
    fi
else
    warn "semgrep not found; skipping Gate 1. Install: pip install semgrep"
fi

echo ""

# ── Gate 2: Trufflehog v3 (secrets) ───────────────────────────────────────
echo -e "${BOLD}Gate 2: Secrets (Trufflehog v3)${RESET}"
if command -v trufflehog &>/dev/null; then
    set +e
    trufflehog filesystem \
        --only-verified \
        --config="$REPO_ROOT/.trufflehog/config.yml" \
        "$TARGET" 2>&1 | tee "$REPORT_DIR/trufflehog-report.txt"
    TH_EXIT=${PIPESTATUS[0]}
    set -e
    if [ "$TH_EXIT" -eq 0 ]; then
        pass "Trufflehog: no verified secrets"
    else
        fail "Trufflehog: verified secrets detected — see $REPORT_DIR/trufflehog-report.txt"
        GATE_FAILURES=$((GATE_FAILURES + 1))
    fi
else
    warn "trufflehog not found; skipping Gate 2."
    warn "Install: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
fi

echo ""

# ── Gate 3: Bandit (Python AST) ────────────────────────────────────────────
echo -e "${BOLD}Gate 3: Python Security (Bandit)${RESET}"
if command -v bandit &>/dev/null; then
    set +e
    bandit \
        -r "$TARGET" \
        -c "$REPO_ROOT/bandit.yml" \
        -f json -o "$REPORT_DIR/bandit-report.json" \
        --exit-zero
    bandit \
        -r "$TARGET" \
        -c "$REPO_ROOT/bandit.yml"
    BANDIT_EXIT=$?
    set -e
    if [ "$BANDIT_EXIT" -eq 0 ]; then
        pass "Bandit: no medium/high issues"
    else
        fail "Bandit: issues detected — see $REPORT_DIR/bandit-report.json"
        GATE_FAILURES=$((GATE_FAILURES + 1))
    fi
else
    warn "bandit not found; skipping Gate 3. Install: pip install bandit==1.8.6"
fi

echo ""

# ── Gate 4: pip-audit (dependency CVEs) ────────────────────────────────────
echo -e "${BOLD}Gate 4: Dependencies (pip-audit)${RESET}"
if command -v pip-audit &>/dev/null; then
    FOUND_REQ=0
    AUDIT_FAILED=0
    while IFS= read -r -d '' req; do
        # Skip vendored clones
        case "$req" in
            *eval/cloned_repos*) continue ;;
        esac
        info "Auditing $req"
        set +e
        pip-audit -r "$req" --strict 2>&1 | tee -a "$REPORT_DIR/pip-audit-report.txt"
        if [ "${PIPESTATUS[0]}" -ne 0 ]; then
            AUDIT_FAILED=1
        fi
        set -e
        FOUND_REQ=1
    done < <(find "$TARGET" -name "requirements*.txt" -print0)

    if [ "$FOUND_REQ" -eq 0 ]; then
        info "No requirements*.txt found; skipping pip-audit."
    elif [ "$AUDIT_FAILED" -eq 0 ]; then
        pass "pip-audit: no known CVEs"
    else
        fail "pip-audit: vulnerable dependencies — see $REPORT_DIR/pip-audit-report.txt"
        GATE_FAILURES=$((GATE_FAILURES + 1))
    fi
else
    warn "pip-audit not found; skipping Gate 4. Install: pip install pip-audit==2.7.3"
fi

echo ""

# ── Summary ────────────────────────────────────────────────────────────────
echo -e "${BOLD}=== Pipeline Summary ===${RESET}"
if [ "$GATE_FAILURES" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All gates passed. Ready to push.${RESET}"
    exit 0
else
    echo -e "${RED}${BOLD}$GATE_FAILURES gate(s) failed. Fix issues before pushing.${RESET}"
    echo -e "Reports saved to: $REPORT_DIR"
    exit 1
fi
