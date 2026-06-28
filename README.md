# iocsift 🔎

[![CI](https://github.com/BL3IP/iocsift/actions/workflows/ci.yml/badge.svg)](https://github.com/BL3IP/iocsift/actions/workflows/ci.yml)

> Extract and enrich indicators of compromise (IOCs) from messy text and logs — **zero runtime dependencies**, pure Python stdlib.

![python](https://img.shields.io/badge/python-3.9%2B-blue)
![tests](https://img.shields.io/badge/tests-17%20passing-brightgreen)
![license](https://img.shields.io/badge/license-MIT-green)

`iocsift` is a from-scratch CLI for SOC analysts and DFIR/threat-intel work. Paste in a
firewall log, an EDR alert, or a threat report and it pulls out the IPs, domains, URLs,
emails, file hashes, and CVEs — automatically **re-fanging** defanged indicators
(`hxxp://evil[.]com`, `user[at]bad[.]net`) so nothing is missed — then enriches each one.

## Goal
Build a genuinely useful, dependency-free open-source security tool that turns unstructured
incident text into structured, enriched, machine-readable IOCs — the kind of utility a blue
team actually keeps in their toolbox.

## Features
- **9 IOC types:** IPv4, IPv6, domain, URL, email, MD5, SHA1, SHA256, CVE.
- **Auto re-fang:** detects `hxxp`, `[.]`, `(.)`, `[dot]`, `[at]`, `(at)` defang styles.
- **Smart filtering:** skips filenames (`report.txt`, `notes.pdf`) that look like domains;
  never double-counts a URL/email host as a bare domain.
- **Offline enrichment (default):** IP scope (private/global/loopback/reserved/multicast),
  hash algorithm, URL parts, CVE year, email domain.
- **Optional online enrichment (`--online`):** reverse DNS + **keyless** Shodan
  [InternetDB](https://internetdb.shodan.io/) (open ports, hostnames, tags, known CVEs).
  Fails soft — never crashes a scan if the network is down.
- **3 output formats:** `table`, `json`, `csv`. Reads files or stdin.

## Exact Setup Commands
```powershell
cd C:\Users\banlv\cyber\10-oss-security-tool
& "C:\Users\banlv\AppData\Local\Programs\Python\Python312\python.exe" -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"   # editable install + pytest

# run tests
.\.venv\Scripts\python.exe -m pytest -q

# use it
.\.venv\Scripts\iocsift.exe samples\sample_log.txt
.\.venv\Scripts\iocsift.exe samples\sample_log.txt -f json -t ipv4,sha256
Get-Content somelog.txt | .\.venv\Scripts\iocsift.exe --online
```

Docker (image definition included):
```bash
docker build -t iocsift .
docker run --rm -i iocsift < somelog.txt
```

## Proof It Works
**17/17 unit tests pass** (`pytest -q` → `17 passed in 0.04s`).

Extracting from the bundled `samples/sample_log.txt`:
```text
TYPE    VALUE
------  ----------------------------------------------------------------
cve     CVE-2017-0144
cve     CVE-2021-44228
domain  bad-c2.example.org
email   attacker@bad-actor.net
ipv4    10.0.0.5
ipv4    185.220.101.34
ipv4    45.83.122.10
md5     44d88612fea8a8f36de82e1278abb02f
sha256  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
url     http://evil-domain.com/payload.bin

Total: 10 IOCs (cve=2, domain=1, email=1, ipv4=3, md5=1, sha256=1, url=1)
```
Note how `hxxp://evil-domain[.]com`, `attacker[at]bad-actor[.]net`, and `bad-c2(.)example(.)org`
were all re-fanged, while `report.txt` was correctly **not** treated as a domain.

Live online enrichment (`"1.1.1.1" | iocsift --online -f json`):
```json
{
  "value": "1.1.1.1", "type": "ipv4",
  "enrichment": {
    "is_global": true,
    "reverse_dns": "one.one.one.one",
    "shodan_internetdb": { "ports": [53, 80, 443, 2083, 8880], "hostnames": ["one.one.one.one"], "vulns": [] }
  }
}
```

## Screenshots
See [`./screenshots/`](./screenshots). Add: the table output in a terminal, and a JSON
enrichment result (offline + `--online`).

## My Custom Extensions
- **Keyless live threat enrichment** via Shodan InternetDB (no API key, no cost) with a proper
  `User-Agent` (fixed an initial `403`) — surfaces open ports and known CVEs per public IP.
- **Defang/refang engine** covering 6 obfuscation styles so IOCs copied from reports/Slack
  are still detected.
- **False-positive guard**: a file-extension denylist + URL/email host de-duplication so the
  output is clean enough to feed straight into a SIEM or ticket.
- **Packaging done right**: `src/` layout, console-script entry point, `python -m iocsift`,
  Dockerfile (non-root), and a GitHub Actions matrix CI across Python 3.9–3.12.

## Resume Bullet Points
- Designed and shipped **`iocsift`**, a zero-dependency open-source Python CLI that extracts and
  enriches 9 IOC types from unstructured logs, with automatic defang/refang and JSON/CSV/table output.
- Added **keyless live threat enrichment** (Shodan InternetDB + reverse DNS) and packaged the tool
  for distribution (pip console-script, `python -m`, Docker, GitHub Actions CI across 4 Python versions).
- Built a **17-test pytest suite** (extraction, defang round-trips, IP/hash/CVE classification) giving
  deterministic, offline-verifiable coverage.

## Next-Level Ideas
- STIX 2.1 / MISP-feed export so IOCs drop straight into a TIP.
- Pluggable enrichers (AbuseIPDB, VirusTotal, GreyNoise) behind an interface, key-gated.
- A confidence score per IOC (TLD entropy, allowlist of benign domains).
- Publish to PyPI + a Reddit/r/netsec post to chase the 50★ goal.

---
status: ✅ complete & tested
```
✅ PROJECT COMPLETE & FULLY TESTED in its isolated folder. All works. Ready for portfolio.
```
