#!/usr/bin/env bash
# The headline: run every abuse case and require zero policy violations.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== abuse suite: scope escalation, replay, over-rate, injection, forgery ==="
.venv/bin/pytest tests/test_abuse_suite.py -v --no-header -p no:warnings

echo
echo "=== full suite (unit + integration over real MCP HTTP transport) ==="
.venv/bin/pytest -q --no-header -p no:warnings

echo
echo "=== ABUSE SUITE PASSED: zero policy violations ==="
