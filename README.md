# dnsbleed
**DNS Response Timing & Privacy Analyzer**

`dnsbleed` is a high-precision DNS timing analysis and privacy evaluation tool. By mapping nanosecond-scale latency deltas across different protocols and resolvers, it mathematically detects hidden network configurations, VPN leaks, transparent DNS proxies, and other data bleeds.

## Features
- **Upstream Bleed Detection**: Statistically correlates the latency fingerprints of unknown or local resolvers against known public resolvers to expose covert forwarding and transparent proxy intercepts.
- **Cache Snooping (Data Bleed)**: Exploits resolver caching mechanisms to measure microsecond latency drops, determining if a specific domain was recently queried by someone else on the network.
- **Misconfiguration & Privacy Checks**: Aggressively probes resolvers for:
  - **EDNS Client Subnet (ECS) Leaks**: Checks if the resolver broadcasts your subnet to authoritative servers.
  - **NXDOMAIN Hijacking**: Detects if non-existent domains are being intercepted and redirected to ad servers.
  - **Open Resolver Status**: Identifies misconfigured servers vulnerable to DNS amplification attacks.
- **Multi-Protocol & Custom Query Type Support**: Seamlessly tests across `udp`, `tcp`, `dot` (DNS-over-TLS), and `doh` (DNS-over-HTTPS), with support for custom query types (e.g., `A`, `AAAA`, `MX`, `TXT`, `CNAME`).
- **DNSSEC Validation Validation**: Verifies that the resolver validates signature integrity and blocks invalid signature chains (e.g. `dnssec-failed.org`).
- **Rate-Limiting & Burst Auditing**: Evaluates resolver packet loss and connection stability under rapid burst traffic.
- **Stealth & Evasion**: Utilizes random subdomain prefixing (`--random-subdomains`), configurable query sleep intervals (`--jitter`), and SOCKS5 proxy support.

## Installation
```bash
git clone https://github.com/Baba01hacker666/dnsbleed.git
cd dnsbleed
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

## Usage
### Basic Latency Mapping
Test standard UDP and TCP latencies across multiple resolvers with custom query types:
```bash
dnsbleed -d example.com -r 8.8.8.8,1.1.1.1 -p udp,tcp -q A,AAAA -c 10
```

You can also read domains and resolvers from files (one per line):
```bash
dnsbleed -D domains.txt -R resolvers.txt -c 20
```

### Upstream Bleed / Leak Detection
Test your local ISP or VPN resolver against a public provider to see if traffic is leaking:
```bash
dnsbleed -d google.com -r 192.168.1.1,8.8.8.8,1.1.1.1 -c 15
```

### Cache Snooping Attack
Determine if `target-website.com` has been recently visited by another user on the target resolver:
```bash
dnsbleed -d target-website.com -r 10.0.0.1 --cache-snoop -c 5
```

### Privacy, DNSSEC & Misconfiguration Checks
Test modern protocols (DoH and DoT) while scanning for ECS leaks, hijacking, and DNSSEC enforcement:
```bash
dnsbleed -d github.com -r 8.8.8.8 -p udp --check-misconfigs --check-dnssec --check-rate-limit
```

### SOCKS5 Proxy Routing
Route tests through Tor or another proxy (fully isolates DoH and TCP traffic):
```bash
dnsbleed -d google.com -r 1.1.1.1 -p dot,doh --proxy socks5://127.0.0.1:9050
```

## CLI Options
```text
options:
  -h, --help            show this help message and exit
  -d DOMAINS, --domains DOMAINS
                        Comma-separated domains to query
  -D DOMAINS_FILE, --domains-file DOMAINS_FILE
                        File containing list of domains (one per line)
  -r RESOLVERS, --resolvers RESOLVERS
                        Comma-separated resolvers (IP or URL)
  -R RESOLVERS_FILE, --resolvers-file RESOLVERS_FILE
                        File containing list of resolvers (one per line)
  -c COUNT, --count COUNT
                        Number of queries per resolver (default: 50)
  -p PROTOCOLS, --protocols PROTOCOLS
                        Comma-separated protocols: udp, tcp, dot, doh (default: udp)
  -q QTYPES, --qtypes QTYPES
                        Comma-separated query types: A, AAAA, MX, TXT, NS, CNAME (default: A)
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 10)
  --timeout TIMEOUT     Query timeout in seconds (default: 2.0)
  --jitter JITTER       Max random jitter between queries in seconds (default: 0.0)
  --random-subdomains   Prefix queries with random subdomains to bypass cache
  --cache-snoop         Enable cache snooping to bleed info on recently visited domains
  --check-misconfigs    Check for NXDOMAIN hijacking, Open Resolver status, and ECS leaks
  --check-dnssec        Perform DNSSEC validation tests (verifies AD flag & fails on invalid sigs)
  --check-rate-limit    Detect resolver rate-limiting under burst query loads
  --proxy PROXY         Proxy URL (e.g. socks5://127.0.0.1:9050)
  -o OUTPUT, --output OUTPUT
                        Output file base name (default: dnsbleed_report)
  -f FORMAT, --format FORMAT
                        Comma-separated output formats: csv, json, html (default: csv,json,html)
```

## Detailed Analysis Mechanics

### DNSSEC validation Checking (`--check-dnssec`)
When this check is executed, the tool does two things:
1. Queries a standard DNSSEC-signed domain (`cloudflare.com`) with the `DO` (DNSSEC OK) bit enabled. It checks if the resolver sets the **AD (Authentic Data)** flag and returns **RRSIG signatures** in the response.
2. Queries `dnssec-failed.org` (a domain with intentionally broken DNSSEC signatures). A validation-enforcing resolver must return `SERVFAIL` (blocking the request), while a non-enforcing resolver will return `NOERROR`.

### Rate-Limiting Detection (`--check-rate-limit`)
Rapidly bursts a sequence of 20 random query requests to each resolver. It calculates the request drop/loss rate to indicate if the resolver implements **Response Rate Limiting (RRL)** or traffic shaping rules under burst loads.

## Output Formats
Results are printed cleanly to standard output, but raw metrics can also be exported to `csv`, `json`, and interactive `html` charts by passing `-f csv,json,html`.

