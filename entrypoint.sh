#!/bin/bash
# Entrypoint: process log files with scqlog then serve outputs over HTTP

set -e

echo "=== scqlog: processing log files ==="
scqlog data/*.log

echo "=== Starting HTTP server on port 8000 ==="
cd /app/data
exec python -m http.server 8000
