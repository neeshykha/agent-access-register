#!/bin/sh
# Run the access register against the live config and write the page named in it.
# Read-only: it opens settings files, the scheduler registry, SKILL.md files, and
# the scripts they name. It never opens a credential store and never sends anything.
#
#   ./run_register.sh            exit 0 clean, 1 findings, 2 incomplete
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/access_register.py" --config "$HERE/local/live.config.json" "$@"
