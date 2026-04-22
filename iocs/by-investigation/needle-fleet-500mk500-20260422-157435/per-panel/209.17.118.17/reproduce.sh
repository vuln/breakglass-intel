#!/bin/bash
# Reproduce Needle panel fingerprint for 209.17.118.17 (verified 2026-04-22 02:53 UTC)
set -e
HOST="209.17.118.17"

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
echo "Expected: 760739aae8a244bcba6880a9adc1ce2b37e4c43f20e2f3368fc6da10178c8ff8  (size 911193)"

echo "[5] Protected endpoint (should 401)"
curl -sk -m 10 -w "HTTP=%{http_code}\n" -o /dev/null "http://$HOST:3000/api/v2/users"
