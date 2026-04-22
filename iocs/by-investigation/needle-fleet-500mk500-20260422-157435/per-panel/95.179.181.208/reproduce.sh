#!/bin/bash
# Reproduce Needle panel fingerprint for 95.179.181.208 (verified 2026-04-22 02:53 UTC)
set -e
HOST="95.179.181.208"

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
echo "Expected: b3a6be7c03a61d4de97e85c15fab7aa344efd0886ca688c9faff510a0c2d0ab8  (size 1110784)"

echo "[5] Protected endpoint (should 401)"
curl -sk -m 10 -w "HTTP=%{http_code}\n" -o /dev/null "http://$HOST:3000/api/v2/users"
