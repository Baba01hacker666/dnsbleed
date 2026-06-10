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
- **Multi-Protocol Support**: Seamlessly tests across `udp`, `tcp`, `dot` (DNS-over-TLS), and `doh` (DNS-over-HTTPS).
- **Stealth & Evasion**: Utilizes random subdomain prefixing (`--random-subdomains`), configurable query sleep intervals (`--jitter`), and SOCKS5 proxy support.

## Installation
```bash
git clone https://github.com/baba01hacker/dnsbleed.git
cd dnsbleed
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
### Basic Latency Mapping
Test standard UDP and TCP latencies across multiple resolvers:
```bash
python3 dnsbleed.py -d example.com -r 8.8.8.8,1.1.1.1 -p udp,tcp -c 10
```

### Upstream Bleed / Leak Detection
Test your local ISP or VPN resolver against a public provider to see if traffic is leaking:
```bash
python3 dnsbleed.py -d google.com -r 192.168.1.1,8.8.8.8,1.1.1.1 -c 15
```

### Cache Snooping Attack
Determine if `target-website.com` has been recently visited by another user on the target resolver:
```bash
python3 dnsbleed.py -d target-website.com -r 10.0.0.1 --cache-snoop -c 5
```

### Privacy & Misconfiguration Checks
Test modern protocols (DoH and DoT) while scanning for ECS leaks and hijacking:
```bash
python3 dnsbleed.py -d github.com -r https://1.1.1.1/dns-query,8.8.8.8 -p doh,dot --check-misconfigs
```

### SOCKS5 Proxy Routing
Route tests through Tor or another proxy (fully isolates DoH and TCP traffic):
```bash
python3 dnsbleed.py -d google.com -r 1.1.1.1 -p dot,doh --proxy socks5://127.0.0.1:9050
```

## Output Formats
Results are printed cleanly to standard output, but raw metrics can also be exported to `csv` and `json` by passing `-f csv,json`.
