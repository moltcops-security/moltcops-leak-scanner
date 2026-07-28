#!/usr/bin/env bash
# scan_repo.sh — MoltCops leak-scanning pipeline
#
# Deep-scan one repository (full git history) for leaked secrets using
# trufflehog (800+ detectors) + gitleaks (MoltCops agent-ecosystem rules).
#
# Verification is OFF in both tools, deliberately: trufflehog's default
# mode calls the provider with the found credential. We never use a found
# credential — classification is offline (bip39_filter.py, wallet_check.py)
# and triage is manual. There is no flag in this toolkit to turn
# verification on. safety_self_test.py asserts the flag stays on.
#
# Outputs go OUTSIDE this workspace (default ~/moltcops-secure/) per
# CLAUDE.md rule 2: the JSON reports contain raw Secret values and must
# never exist inside the repo (backups, sync, editor indexes, agents).
#
# Usage:
#   ./scan_repo.sh https://github.com/owner/repo
#   MOLTCOPS_OUTPUT_DIR=/some/dir ./scan_repo.sh https://github.com/owner/repo
#
# Install (v3 is a Go binary — NOT pip):
#   brew install trufflesecurity/trufflehog/trufflehog    # macOS
#   curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin   # Linux

set -euo pipefail
URL="${1:?usage: $0 <repo-url>}"

# Never leave a scan report inside the repo (rule 2). Default outside the
# workspace; overridable for air-gapped/CI boxes via MOLTCOPS_OUTPUT_DIR.
OUT_ROOT="${MOLTCOPS_OUTPUT_DIR:-$HOME/moltcops-secure}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_ROOT/scan-${STAMP}"

# Resolve the config relative to THIS SCRIPT so the scan works from any
# working directory (a CWD-relative path used to silently no-op the gitleaks
# half of every scan run from anywhere but the checkout root).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/moltcops-rules.toml"

# Fail loudly if a scanner is missing — a silent exit-0 here used to be read
# as "repo is clean". (--exit-code 0 below already suppresses gitleaks'
# leaks-found exit, so there is no reason to swallow real failures.)
for tool in trufflehog gitleaks; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: $tool not installed — see README Setup. Aborting rather than reporting a fake 'clean'." >&2
    exit 1
  }
done

mkdir -p "$OUT"

echo "[1/2] trufflehog (full history, verification OFF)..."
rc=0
trufflehog git "$URL" --no-verification --json > "$OUT/trufflehog.json" || rc=$?
[ "$rc" -eq 0 ] || echo "warning: trufflehog exited $rc — treat its report as incomplete" >&2

echo "[2/2] gitleaks (MoltCops agent-ecosystem rules)..."
rc=0
gitleaks git "$URL" --config "$CONFIG" \
  --report-format json --report-path "$OUT/gitleaks.json" --exit-code 0 || rc=$?
[ "$rc" -eq 0 ] || echo "warning: gitleaks exited $rc (clone failure?) — treat its report as incomplete" >&2

# A zero-byte report means the scanner failed, not that the repo is clean.
for f in trufflehog gitleaks; do
  [ -s "$OUT/$f.json" ] || echo "warning: $OUT/$f.json is empty — verify the scan actually ran" >&2
done

echo ""
echo "results in $OUT/ (outside the repo, per rule 2) — review manually, then:"
echo "  seed-phrase candidates  ->  python3 \"$SCRIPT_DIR/bip39_filter.py\" <file>"
echo "  eth private keys        ->  python3 \"$SCRIPT_DIR/wallet_check.py\" < key.txt"
echo "                              (or run with no argument to be prompted;"
echo "                               never pass keys as argv — shell history keeps them)"
echo "  everything else         ->  format + context review in browser"
echo ""
echo "Reminders: never use a found credential. Never move funds."
echo "Notify the owner (see README notification template). Publish only"
echo "redacted, aggregate statistics."
