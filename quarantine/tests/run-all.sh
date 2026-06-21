#!/usr/bin/env bash
#
# run-all.sh — run the quarantine skill's full offline test suite.
# Usage: bash ~/.claude/skills/quarantine/tests/run-all.sh
#
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0
echo "### guards.test.sh"; bash "$DIR/guards.test.sh" || rc=1
echo; echo "### scan.test.sh"; bash "$DIR/scan.test.sh" || rc=1
echo; echo "### acquire.test.py"; python3 "$DIR/acquire.test.py" || rc=1
echo; [ "$rc" -eq 0 ] && echo "ALL SUITES PASSED" || echo "SOME SUITES FAILED"
exit "$rc"
