#!/bin/bash
# Reproduce Needle panel fingerprint for 178.16.54.109 (verified 2026-04-22 02:53 UTC)
set -e
HOST="178.16.54.109"

echo "[1] Root HTML + headers"
curl -sk -m 15 -D root-headers.txt -o root.html "http://$HOST:3000/"

echo "[2] Extract bundle URL from root HTML"
BUNDLE=$(grep -oE "/assets/index-[A-Za-z0-9_-]+\.js" root.html | head -1)
echo "Bundle: $BUNDLE"

echo "[3] Health endpoint"
curl -sk -m 10 "http://$HOST:3000/api/v2/health" > health.json
cat health.json; echo

echo "[4] Download bundle + verify SHA-256"
curl -sk -m 30 -o bundle.js "http://$HOST:3000$BUNDLE"
sha256sum bundle.js
echo "Expected: 9bd9bd7bc0b4d8dba5fd7f3f3744b30c6c4a00ee5d5ccb8b2b4cce23f0eec0eb  (size 913304)"

echo "[5] Protected endpoint (should 401)"
curl -sk -m 10 -w "HTTP=%{http_code}\n" -o /dev/null "http://$HOST:3000/api/v2/users"
