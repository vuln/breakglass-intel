# Needle MaaS Fleet — April 22, 2026

Raw artifacts and reproduction material for the Needle fleet mapping published at:

> **Blog:** https://intel.breakglass.tech/post/needle-fleet-mapping-9-live-panels-kasimov-pivot
> **Tipster:** [Mikhail Kasimov (@500mk500)](https://twitter.com/500mk500)
> **Date of capture:** 2026-04-22 02:53 UTC
> **Original Needle report:** https://intel.breakglass.tech/post/needle-crimeware-platform-twizt-phorpiex-wallet-drainer-960m-credentials

## Scope

Nine live Needle MaaS customer panels confirmed on TCP 3000, each serving a separately-compiled Vite bundle with a distinct SHA-256 hash. Four additional IPs from the tipster's list did not respond during the sweep and are included as a hold set.

## Contents

```
panels.csv                — One row per live+hold panel; bundle hash, size, uptime, ASN
panels.json               — Same data, machine-readable
per-panel/<ip>/
  root.html               — Full HTTP response body for GET /
  root-headers.txt        — Full HTTP response headers for GET /
  health.json             — Response from GET /api/v2/health
  bundle.sha256           — SHA-256 checksum of the Vite bundle
  reproduce.sh            — Shell script that recaptures this panel's fingerprint
per-bundle-strings/<ip>.unique.txt
                          — Strings (6+ chars) present in this panel's bundle
                            and NOT in any of the other eight. Useful for
                            per-tenant differential analysis.
bundles/<ip>--index-<hash>.js
                          — The raw Vite-built React SPA bundle as served by
                            each panel at capture time. These are JavaScript
                            text files (not executables); they render the
                            browser-stealer panel UI.
```

## Verification

For any live panel, re-run `per-panel/<ip>/reproduce.sh` to confirm:

1. Panel still returns HTTP 200 on `/`.
2. Root HTML title is `Needle`.
3. Bundle filename under `/assets/index-<hash>.js`.
4. `/api/v2/health` returns `{"status":"healthy",...}`.
5. Bundle SHA-256 matches `bundle.sha256`.

The bundles in `bundles/` are the exact bytes served at capture time. A mismatch on a later run means the operator has rebuilt or redeployed.

## Safety

These bundles are the client-side SPA for the Needle operator panel. They do **not** execute automatically; they are JavaScript source text. Analysts can open them with any text editor, AST tool, or beautifier. Do not execute them as privileged scripts; treat them as untrusted input.

The bundles do not contain the Phorpiex worm, the wallet-drainer stage, or the Monero miner — those are server-issued payloads documented in the original April 20 report. The bundles are only the panel UI.

## Scope not included

- Shadow C2 panel captures (separate investigation, out of scope here).
- Authenticated admin-panel data (we did not authenticate).
- Server-side code (we did not exploit).
- Any PII of Needle victims.

## Citation

If this data is useful to your own research, please cite:

> Breakglass Intelligence, "Needle Fleet — Nine Live Customer Panels Across Five ASNs Mapped After Public Disclosure," April 22, 2026. Tipster credit: Mikhail Kasimov (@500mk500).

Prior reporting welcome — please reply to the blog or open an issue on this repo if you have earlier work we should credit.
