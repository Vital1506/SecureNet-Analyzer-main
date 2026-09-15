#!/usr/bin/env bash
#
# SecureNet Analyzer launcher (POSIX shell).
# Forwards all arguments to Main.py.
#
# Quick examples:
#   ./run.sh block --list-blocks --offline
#   ./run.sh block-activate --dry-run
#   ./run.sh intel --intel-source sample --intel-auto-block
#   ./run.sh c --pc 50 --summary --alert-on 50 --alert-file alerts.log
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if command -v python3 >/dev/null 2>&1; then
  exec python3 Main.py "$@"
else
  exec python Main.py "$@"
fi
