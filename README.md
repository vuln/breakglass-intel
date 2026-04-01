# Breakglass Intelligence

Detection rules, IOCs, and threat intelligence from [Breakglass Intelligence](https://intel.breakglass.tech) investigations.

## Stats

| Category | Count |
|----------|-------|
| IPv4 addresses | 1,253 |
| Domains | 1,717 |
| URLs | 797 |
| SHA256 hashes | 1,031 |
| SHA1 hashes | 149 |
| MD5 hashes | 442 |
| YARA rules | 103 |
| Suricata rules | 55 |
| STIX bundles | 24 |
| KQL queries | 16 |
| Nuclei templates | 4 |
| Investigations | 232 |

## Structure

```
breakglass-intel/
├── yara/                          — 103 YARA detection rules
├── suricata/                      — 55 Suricata/Snort network rules
├── kql/                           — Microsoft Defender/Sentinel KQL queries
├── nuclei/                        — Nuclei scanner templates
├── iocs/
│   ├── all-ipv4.txt               — 1,253 IPv4 indicators
│   ├── all-domains.txt            — 1,717 domain indicators
│   ├── all-urls.txt               — 797 URL indicators (defanged)
│   ├── all-sha256.txt             — 1,031 SHA256 hashes
│   ├── all-sha1.txt               — 149 SHA1 hashes
│   ├── all-md5.txt                — 442 MD5 hashes
│   ├── all-file-indicators.json   — Filenames, paths, registry keys, mutexes
│   ├── feed.json                  — Machine-readable IOC feed index
│   └── by-investigation/          — 232 per-investigation IOC files
└── stix/                          — 24 STIX 2.1 intelligence bundles
```

## Featured Investigations

| Date | Investigation | Tags |
|------|-------------|------|
| 2026-04-01 | [SumUp Phishing Kit — Open Panel, Moroccan Operators](https://intel.breakglass.tech/post/sumup-phishing-kit-open-panel-moroccan-operators-7-deployments) | phishing, credential-harvesting |
| 2026-04-01 | [Trojanized Zelix KlassMaster — DoH C2 via Piracy](https://intel.breakglass.tech/post/trojanized-zelix-klassmaster-doh-c2-mcleaks-piracy-supply-chain) | supply-chain, java, dns-over-https |
| 2026-04-01 | [SERPENTINE Goes German — Dual RAT, Custom Donut](https://intel.breakglass.tech/post/serpentine-cloud-german-wave-dual-rat-custom-donut-chaskey) | dcrat, xenorat, donut |
| 2026-04-01 | [Boeing RFQ / NKFZ5966 — Cobalt Strike](https://intel.breakglass.tech/post/boeing-rfq-nkfz5966-cobalt-strike-6-stage-filemail) | cobalt-strike, spear-phishing |
| 2026-04-01 | [LofyGang NYX Stealer — npm, Still Live](https://intel.breakglass.tech/post/lofygang-nyx-stealer-npm-supply-chain-still-live) | npm, supply-chain |
| 2026-04-01 | [InvisibleFerret — DPRK Lazarus-Kimsuky](https://intel.breakglass.tech/post/invisibleferret-contagious-interview-dprk-lazarus-kimsuky-crossover) | dprk, lazarus, kimsuky |
| 2026-04-01 | [ClearFake — 24 Domains, Zero Detection](https://intel.breakglass.tech/post/clearfake-aerovector-webdav-24-domains-zero-detection-payloads) | clearfake, webdav |
| 2026-04-01 | [GlassWorm — Solana Blockchain C2](https://intel.breakglass.tech/post/glassworm-wave3-solana-blockchain-c2-rotation-forensics) | solana, blockchain-c2 |
| 2026-04-01 | [SilverFox — 30 Samples, Phone Farm](https://intel.breakglass.tech/post/silverfox-valleyrat-scam-compound-lures-phone-farm-front-apr2026) | silverfox, valleyrat |
| 2026-04-01 | [SheetRAT — Pinggy Tunnel C2](https://intel.breakglass.tech/post/sheetrat-pinggy-tunnel-c2-32-plugin-rat-builder) | pinggy, tunnel-c2 |
| 2026-04-01 | [VENON — Rust Banker, 3 Fraud Engines](https://intel.breakglass.tech/post/venon-rust-brazilian-banker-screenshot-proof-overlays-pix-swap) | banking-trojan, rust |
| 2026-04-01 | [RatonRAT MaaS Unmasked](https://intel.breakglass.tech/post/ratonrat-maas-platform-silly-developer-unmasked) | maas, rat |
| 2026-04-01 | [PlugX — 2016 COM in 2026 Build](https://intel.breakglass.tech/post/plugx-decade-reuse-2016-com-type-library-mustang-panda) | plugx, mustang-panda |
| 2026-03-31 | [Riptide — 271K-Connection Proxy Empire](https://intel.breakglass.tech/post/riptide-proxy-empire-pprof-exposure) | proxy, pprof |
| 2026-03-31 | [Mustang Panda Vietnam — 6-Layer Shellcode](https://intel.breakglass.tech/post/mustang-panda-vietnam-corruption-scandal-6-layer-shellcode-injector) | mustang-panda, donut |
| 2026-03-31 | [HexReaper — GitHub Gist Dead-Drop](https://intel.breakglass.tech/post/hexreaper-kortex-rat-github-gist-dead-drop-c2) | nodejs, github |
| 2026-03-31 | [Operation TeomSlive — 88 Pivots From Dead Domain](https://intel.breakglass.tech/post/operation-teomslive-authoritative-dns-bypass-malware-gambling-fraud) | osint, dns |

[View all 232 investigations at intel.breakglass.tech](https://intel.breakglass.tech)

## Usage

### YARA
```bash
yara -r yara/breakglass-all.yar <sample_or_directory>
```

### Suricata
```bash
suricata -S suricata/breakglass-all.rules -r capture.pcap
```

### KQL (Microsoft Defender / Sentinel)
Import queries from `kql/` into Advanced Hunting or Analytics Rules.

### IOC Feed
Machine-readable feed at `iocs/feed.json`. Per-investigation IOCs at `iocs/by-investigation/<slug>.json`.

```python
import json, urllib.request

feed = json.loads(urllib.request.urlopen(
    "https://raw.githubusercontent.com/vuln/breakglass-intel/main/iocs/feed.json"
).read())

print(f"Total indicators: {sum(feed['total_indicators'].values())}")
```

### STIX
Import bundles from `stix/` into your TIP (MISP, OpenCTI, ThreatConnect, etc.).

## Citation

```bibtex
@misc{breakglass2026,
  author = {Breakglass Intelligence},
  title = {Breakglass Intelligence — Detection Rules and IOCs},
  year = {2026},
  publisher = {GitHub},
  url = {https://github.com/vuln/breakglass-intel}
}
```

## License

Detection rules: [MIT License](LICENSE). IOCs and STIX bundles: [TLP:WHITE](https://www.first.org/tlp/).

## Contact

- Web: [intel.breakglass.tech](https://intel.breakglass.tech)
- Twitter: [@BreakGlassIntel](https://x.com/BreakGlassIntel)
- Email: security@breakglass.tech
