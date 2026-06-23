# dnsbleed

**DNS Response Timing Analyzer**  
*Resolver Leak Detection via Latency Delta Mapping*

**Author**: baba01hacker  
**Role**: Security Researcher & Red Teamer  
**Published**: For defensive research, adversarial simulation, and DNS privacy analysis

---

## Overview

`dnsbleed` is a precision DNS timing analysis tool designed to detect resolver leaks, misconfigurations, and anomalous behavior through high-resolution latency delta mapping.

It measures nanosecond-scale timing differences between DNS queries sent to different resolvers, identifies timing fingerprints, and detects cases where traffic is being leaked to unintended resolvers (e.g., via OS defaults, VPN leaks, browser DoH, firewall redirects, or supply-chain interference).

This tool is particularly useful for:
- Red team operations (identifying resolver hijacks or monitoring infrastructure)
- Privacy research (detecting DoH/DoT fallback leaks)
- Blue team / detection engineering (building resolver anomaly baselines)
- Firmware/IoT analysis (timing side-channels in embedded resolvers)

---

## Features

- **High-precision timing**: Uses `time.perf_counter_ns()` + statistical modeling
- **Latency Delta Mapping**: Computes deltas across multiple resolvers and query types
- **Multi-protocol support**: UDP, TCP, DoH (HTTPS), DoT (TLS)
- **Stealth & Evasion**: Randomized query patterns, jitter, custom EDNS, source port randomization
- **Parallel execution**: Threaded + asyncio for high-volume sampling
- **Statistical analysis**: Mean, median, stddev, skewness, outlier detection (numpy/scipy)
- **Fingerprinting**: Builds resolver timing signatures
- **Leak detection heuristics**: Compares against baseline, detects unexpected resolver responses
- **Proxy & VPN aware**: SOCKS5/HTTP proxy support, interface binding
- **Raw socket options** (optional, requires root): For advanced timing control
- **Export formats**: JSON, CSV, Markdown report, Plotly visualizations
- **Extensible**: Plugin architecture for custom heuristics

---

## Installation

```bash
git clone https://github.com/baba01hacker/dnsbleed.git
cd dnsbleed
python3 -m pip install -r requirements.txt
