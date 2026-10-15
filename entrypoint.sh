#!/bin/bash
# Entrypoint: process every data/*.log with scqlog, then serve data/ over HTTP.
# Any arguments are passed through to scqlog (e.g. `-pl 2`).

set -e

cd /app/data
shopt -s nullglob
logs=(*.log)

if [ ${#logs[@]} -eq 0 ]; then
    echo "=== scqlog: no .log files found in /app/data (did you mount your log directory?) ==="
else
    echo "=== scqlog: processing ${#logs[@]} log file(s) ==="
    scqlog "$@" "${logs[@]}"
fi

echo "=== Serving /app/data on http://localhost:8000 (Ctrl+C to stop) ==="
exec python -m http.server 8000
