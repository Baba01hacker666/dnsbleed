# dnsbleed Internal Architecture

This document describes the internal execution flow, concurrency model, and heuristic engines that power the `dnsbleed` CLI.

## 1. Initialization and Execution Flow
When the script starts, `argparse` digests the user's input. The `DNSBleed` class is instantiated, which configures necessary proxies:
- **SOCKS/HTTP Proxies**: Standard `udp`, `tcp`, and `dot` traffic is proxied globally by monkeypatching `socket.socket` using the `PySocks` library.
- **DoH Proxying**: Because `dnspython` routes DNS-over-HTTPS via `httpx` (which bypasses standard socket patches), an explicit `httpx.Client(proxy=...)` is instantiated.

The testing phase begins in `run_tests()`.

## 2. Concurrency Model & Data Collection
To measure highly precise metrics without standard sequential blocking, the tool leverages `concurrent.futures.ThreadPoolExecutor`:
- A task is spawned for every unique combination of `(Resolver, Protocol, Domain, Iteration)`.
- Inside the thread, a query is constructed (with optional random subdomains and jitter).
- **Precision Timing**: `time.perf_counter_ns()` is used to measure the nanosecond latency directly surrounding the `dns.query.<protocol>()` network call.
- Tasks are gathered dynamically using `as_completed()`, ensuring no thread bottleneck delays the pipeline.

## 3. Data Normalization
Once all threads resolve, the raw latency dictionaries are collected into `self.results`. 
Because `as_completed()` returns futures in the order they finish rather than the order they were scheduled, faster cached queries often finish before the initial request. The engine mitigates this race condition by sorting the successful results by `iteration_id` before grouping them.

## 4. Heuristic & Bleed Engines
After raw aggregation via Python's standard `statistics` module (mean, median, stdev), execution enters the Heuristics phase.

### A. Upstream Bleed Detection (`detect_leaks`)
The core DNS leak detector works purely on statistical latency fingerprints.
1. It aggregates latencies grouped strictly by **Protocol** to avoid comparing high-latency DoH overhead with low-latency UDP.
2. It iterates through all combinations of resolvers, extracting the Median and Standard Deviation (Variance).
3. If `Resolver A` and `Resolver B` maintain a median difference of `< 10ms` and a standard deviation difference of `< 5ms`, it concludes that their network paths are inherently linked. This implies `Resolver A` is covertly forwarding queries to `Resolver B`.

### B. Cache Snooping (`detect_cache_bleed`)
When `--cache-snoop` is active, the engine exploits resolver TTL caching.
1. It looks at `iteration[0]` as the baseline (assumed uncached).
2. It calculates the median of `iteration[1..N]` as the "warm cache" speed.
3. If `iteration[0]` is incredibly fast (close to the warm cache median), it concludes the domain was *already cached before the script ran*, bleeding out the fact that someone else on that resolver recently visited the domain.

### C. Misconfiguration Checks (`check_misconfigs`)
When requested, the agent pauses mass-threading and sequentially probes each resolver for standard misconfigurations. It dynamically determines the proper protocol to use (e.g., if the user provided `https://1.1.1.1/dns-query`, it natively uses DoH).
- **NXDOMAIN Hijacking**: Queries a 15-character randomized string `[random].com`. If the resolver returns a valid IP (`len(resp.answer) > 0`), it's hijacking traffic.
- **Open Resolver**: Inspects the Response Flags. If `dns.flags.RA` is True and the IP isn't a known public provider, it flags the server.
- **ECS Data Bleed**: Sends a `TXT` query for `o-o.myaddr.l.google.com`. The engine iterates through the `RRset` inspecting the string response. If it contains `edns0-client-subnet`, it reveals the resolver is bleeding the client's internal IP to authoritative systems.

## 5. Exporting
Raw iteration metrics are dumped seamlessly to standard structures, then written directly to `.csv` or `.json` for further third-party analysis.
