#!/usr/bin/env bash
# Demonstrates Invariant on the local, deliberately vulnerable demo app.
set -u
cd "$(dirname "$0")/.."
INV="${INVARIANT:-.venv/bin/invariant}"
REPORT="$(mktemp -t invariant-demo).report.json"

echo "=== 1. Explore the VULNERABLE app (expect a violation) ==="
$INV explore vulnerable_saas.target:vulnerable_adapter --app-dir examples --seed 1 --report "$REPORT"
echo "exit code: $?"

echo
echo "=== 2. Replay the saved scenario on a fresh vulnerable app (expect same violation) ==="
$INV replay "$REPORT" vulnerable_saas.target:vulnerable_adapter --app-dir examples
echo "exit code: $?"

echo
echo "=== 3. Replay the same scenario on the FIXED app (expect PASS) ==="
$INV replay "$REPORT" vulnerable_saas.target:fixed_adapter --app-dir examples
echo "exit code: $?"

echo
echo "=== 4. Explore the FIXED app (expect PASS) ==="
$INV explore vulnerable_saas.target:fixed_adapter --app-dir examples --seed 1
echo "exit code: $?"
