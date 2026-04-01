# Breakglass Intelligence

Detection rules, IOCs, and threat intelligence from [Breakglass Intelligence](https://intel.breakglass.tech) investigations.

## Structure

```
├── yara/          — YARA detection rules
├── suricata/      — Suricata/Snort network rules
├── sigma/         — SIGMA cross-platform detection
├── kql/           — Microsoft Defender/Sentinel KQL queries
├── iocs/          — Structured IOC feeds (JSON)
├── stix/          — STIX 2.1 intelligence bundles
```

## Recent Investigations

| Date | Investigation | Blog Post |
|------|--------------|-----------|
| 2026-04-01 | SERPENTINE#CLOUD German Wave (dcRAT + XenoRAT) | [Read](https://intel.breakglass.tech/post/serpentine-cloud-german-wave-dual-rat-custom-donut-chaskey) |
| 2026-04-01 | Trojanized Zelix KlassMaster (DoH C2) | [Read](https://intel.breakglass.tech/post/trojanized-zelix-klassmaster-doh-c2-mcleaks-piracy-supply-chain) |
| 2026-04-01 | Boeing RFQ / NKFZ5966 (Cobalt Strike) | [Read](https://intel.breakglass.tech/post/boeing-rfq-nkfz5966-cobalt-strike-6-stage-filemail) |
| 2026-04-01 | LofyGang NYX Stealer (npm supply chain) | [Read](https://intel.breakglass.tech/post/lofygang-nyx-stealer-npm-supply-chain-still-live) |
| 2026-04-01 | InvisibleFerret / DPRK Contagious Interview | [Read](https://intel.breakglass.tech/post/invisibleferret-contagious-interview-dprk-lazarus-kimsuky-crossover) |
| 2026-04-01 | ClearFake WebDAV (24 domains, zero detection) | [Read](https://intel.breakglass.tech/post/clearfake-aerovector-webdav-24-domains-zero-detection-payloads) |
| 2026-04-01 | GlassWorm Solana C2 Rotation | [Read](https://intel.breakglass.tech/post/glassworm-wave3-solana-blockchain-c2-rotation-forensics) |
| 2026-03-31 | Riptide Proxy Empire (pprof exposure) | [Read](https://intel.breakglass.tech/post/riptide-proxy-empire-pprof-exposure) |
| 2026-03-31 | Mustang Panda Vietnam (6-layer shellcode) | [Read](https://intel.breakglass.tech/post/mustang-panda-vietnam-corruption-scandal-6-layer-shellcode-injector) |

## Usage

### YARA
```bash
yara -r yara/ <sample_path>
```

### Suricata
```bash
suricata -S suricata/breakglass.rules -r capture.pcap
```

### SIGMA
Convert to your SIEM format using [sigma-cli](https://github.com/SigmaHQ/sigma-cli):
```bash
sigma convert -t splunk sigma/
```

## Citation

```bibtex
@misc{breakglass2026,
  author = {Breakglass Intelligence},
  title = {Breakglass Intelligence Detection Rules},
  year = {2026},
  publisher = {GitHub},
  url = {https://github.com/vuln/breakglass-intel}
}
```

## License

Detection rules are released under [MIT License](LICENSE). IOCs and STIX bundles are [TLP:WHITE](https://www.first.org/tlp/).

## Contact

- Web: [intel.breakglass.tech](https://intel.breakglass.tech)
- Twitter: [@BreakGlassIntel](https://x.com/BreakGlassIntel)
- Email: security@breakglass.tech
