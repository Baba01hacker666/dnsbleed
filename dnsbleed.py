#!/usr/bin/env python3
import argparse
import time
import random
import string
import json
import csv
import sys
import dns.message
import dns.query
import dns.rdatatype
import statistics
import socket
import httpx
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

init(autoreset=True)

class DNSBleed:
    def __init__(self, args):
        self.args = args
        self.results = []
        self.httpx_client = None
        if self.args.proxy:
            if SOCKS_AVAILABLE:
                proxy_type, proxy_addr = self.parse_proxy(self.args.proxy)
                if proxy_type and proxy_addr:
                    host, port = proxy_addr.split(':')
                    socks.set_default_proxy(proxy_type, host, int(port))
                    socket.socket = socks.socksocket
            self.httpx_client = httpx.Client(proxy=self.args.proxy)
            print(f"{Fore.YELLOW}[*] Using proxy: {self.args.proxy}{Style.RESET_ALL}")

        self.public_resolvers = {
            "Google (8.8.8.8)": "8.8.8.8",
            "Cloudflare (1.1.1.1)": "1.1.1.1",
            "Quad9 (9.9.9.9)": "9.9.9.9",
            "OpenDNS (208.67.222.222)": "208.67.222.222"
        }

    def parse_proxy(self, proxy_str):
        if proxy_str.startswith('socks5://'):
            return socks.SOCKS5, proxy_str[9:]
        elif proxy_str.startswith('socks4://'):
            return socks.SOCKS4, proxy_str[9:]
        elif proxy_str.startswith('http://'):
            return socks.HTTP, proxy_str[7:]
        return None, None

    def generate_random_subdomain(self, domain):
        rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"{rand_str}.{domain}"

    def measure_query(self, resolver, domain, qtype, protocol, timeout=2.0):
        qname = self.generate_random_subdomain(domain) if self.args.random_subdomains else domain
        q = dns.message.make_query(qname, qtype)
        q.use_edns(edns=0, payload=1232)

        # Jitter
        if self.args.jitter > 0:
            time.sleep(random.uniform(0, self.args.jitter))

        start = time.perf_counter_ns()
        try:
            if protocol == 'udp':
                resp = dns.query.udp(q, resolver, timeout=timeout)
            elif protocol == 'tcp':
                resp = dns.query.tcp(q, resolver, timeout=timeout)
            elif protocol == 'dot':
                resp = dns.query.tls(q, resolver, timeout=timeout)
            elif protocol == 'doh':
                resp = dns.query.https(q, resolver, timeout=timeout, client=self.httpx_client)
            else:
                return None, "Unknown protocol"
            end = time.perf_counter_ns()
            latency_ms = (end - start) / 1e6
            return latency_ms, None
        except Exception as e:
            return None, str(e)

    def run_tests(self):
        print(f"{Fore.CYAN}[*] Starting DNS Response Timing Analyzer...{Style.RESET_ALL}")
        print(f"Resolvers: {', '.join(self.args.resolvers)}")
        print(f"Domains: {', '.join(self.args.domains)}")
        print(f"Protocols: {', '.join(self.args.protocols)}")
        print(f"Iterations: {self.args.count}\n")

        tasks = []
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for resolver in self.args.resolvers:
                for protocol in self.args.protocols:
                    for domain in self.args.domains:
                        for i in range(self.args.count):
                            tasks.append(
                                executor.submit(
                                    self.measure_query_task, resolver, domain, "A", protocol, i
                                )
                            )

            for future in as_completed(tasks):
                res = future.result()
                if res:
                    self.results.append(res)

        self.analyze_results()

    def measure_query_task(self, resolver, domain, qtype, protocol, iteration):
        latency, err = self.measure_query(resolver, domain, qtype, protocol, timeout=self.args.timeout)
        sys.stdout.write(".")
        sys.stdout.flush()
        return {
            "resolver": resolver,
            "domain": domain,
            "protocol": protocol,
            "iteration": iteration,
            "latency_ms": latency,
            "error": err
        }

    def analyze_results(self):
        print(f"\n\n{Fore.GREEN}[*] Analysis Complete. Computing Statistics...{Style.RESET_ALL}\n")

        if not self.results:
            print(f"{Fore.RED}[!] No results gathered.{Style.RESET_ALL}")
            return

        success_results = [r for r in self.results if r['latency_ms'] is not None]
        success_results.sort(key=lambda x: x['iteration'])

        # Group by (resolver, protocol)
        grouped = {}
        for r in success_results:
            key = (r['resolver'], r['protocol'])
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(r['latency_ms'])

        stats_list = []
        for (resolver, protocol), latencies in grouped.items():
            if not latencies:
                continue

            mean = statistics.mean(latencies)
            median = statistics.median(latencies)
            std = statistics.stdev(latencies) if len(latencies) > 1 else 0.0

            stats_list.append({
                "Resolver": resolver,
                "Protocol": protocol,
                "Count": len(latencies),
                "Mean (ms)": mean,
                "Median (ms)": median,
                "StdDev": std
            })

        if stats_list:
            print(f"{'Resolver':<15} {'Protocol':<10} {'Count':<8} {'Mean (ms)':<15} {'Median (ms)':<15} {'StdDev':<15}")
            for s in stats_list:
                print(f"{s['Resolver']:<15} {s['Protocol']:<10} {s['Count']:<8} {s['Mean (ms)']:<15.6f} {s['Median (ms)']:<15.6f} {s['StdDev']:<15.6f}")

        if self.args.cache_snoop:
            self.detect_cache_bleed(grouped)
        else:
            self.detect_leaks(grouped)

        if self.args.check_misconfigs:
            self.check_misconfigs()

        self.export_results(self.results)

    def detect_cache_bleed(self, grouped):
        print(f"\n{Fore.RED}[!] Executing Cache Snooping (Data Bleed) Analysis...{Style.RESET_ALL}")
        # Cache snooping compares the first query (uncached ideally, though might be cached by others)
        # to subsequent queries to measure the latency delta.
        # It allows us to "bleed" information about whether a target domain was recently visited.

        for (res, prot), lats in grouped.items():
            if len(lats) < 3:
                continue

            first_query_lat = lats[0]
            cached_lats = lats[1:]
            cached_median = statistics.median(cached_lats)

            # If the first query is significantly slower than subsequent ones, it wasn't cached.
            # If the first query is as fast as the cached ones, it was already cached by someone else!
            diff = first_query_lat - cached_median
            if diff < 5.0 and cached_median < 20.0:
                print(f"{Fore.MAGENTA}[BLEED] {res} ({prot}) -> Domain was LIKELY ALREADY CACHED (Someone visited it recently!){Style.RESET_ALL}")
            elif diff >= 5.0:
                print(f"{Fore.CYAN}[SECURE] {res} ({prot}) -> Domain was NOT cached (Latency drop: {diff:.2f}ms after first query){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[INCONCLUSIVE] {res} ({prot}) -> Timing delta too small or latency too high to determine cache status.{Style.RESET_ALL}")

    def detect_leaks(self, grouped):
        print(f"\n{Fore.CYAN}[*] Running Upstream Bleed & Resolver Leak Detection...{Style.RESET_ALL}")

        resolvers = list(set([r for r, p in grouped.keys()]))
        protocols = list(set([p for r, p in grouped.keys()]))

        if len(resolvers) < 2:
            print(f"{Fore.YELLOW}Need at least 2 resolvers to map latency deltas for leak detection.{Style.RESET_ALL}")
            return

        print("[*] Comparing timing fingerprints across resolvers...")
        for prot in protocols:
            print(f"\n  {Fore.CYAN}[ Protocol: {prot.upper()} ]{Style.RESET_ALL}")
            for i, r1 in enumerate(resolvers):
                for r2 in resolvers[i+1:]:
                    d1 = grouped.get((r1, prot), [])
                    d2 = grouped.get((r2, prot), [])

                    if len(d1) < 5 or len(d2) < 5:
                        continue

                    med1 = statistics.median(d1)
                    med2 = statistics.median(d2)
                    std1 = statistics.stdev(d1) if len(d1) > 1 else 0.0
                    std2 = statistics.stdev(d2) if len(d2) > 1 else 0.0

                    diff = abs(med1 - med2)
                    std_diff = abs(std1 - std2)

                    if diff < 10.0 and std_diff < 5.0:
                        print(f"    {Fore.RED}[BLEED DETECTED] Timing fingerprint of '{r1}' matches '{r2}'!{Style.RESET_ALL}")
                        print(f"        -> Median Diff: {diff:.2f}ms | Variance Diff: {std_diff:.2f}ms")
                        print(f"        -> {Fore.YELLOW}Conclusion: Traffic to '{r1}' is likely leaking/forwarding to '{r2}'.{Style.RESET_ALL}")
                    elif diff < 25.0:
                        print(f"    {Fore.YELLOW}[POSSIBLE BLEED] Timing fingerprint of '{r1}' is suspiciously close to '{r2}'.{Style.RESET_ALL}")

    def check_misconfigs(self):
        print(f"\n{Fore.MAGENTA}[*] Running DNS Misconfiguration & Privacy Checks...{Style.RESET_ALL}")
        for resolver in self.args.resolvers:
            print(f"\n{Fore.CYAN}Target Resolver: {resolver}{Style.RESET_ALL}")

            test_protocol = 'udp'
            if resolver.startswith("http"):
                test_protocol = 'doh'
            elif 'dot' in self.args.protocols:
                test_protocol = 'dot'
            elif 'tcp' in self.args.protocols:
                test_protocol = 'tcp'

            # 1. NXDOMAIN Hijacking & Open Resolver Check
            bad_domain = f"{''.join(random.choices(string.ascii_lowercase, k=15))}.com"
            q = dns.message.make_query(bad_domain, "A")
            try:
                if test_protocol == 'udp':
                    resp = dns.query.udp(q, resolver, timeout=self.args.timeout)
                elif test_protocol == 'tcp':
                    resp = dns.query.tcp(q, resolver, timeout=self.args.timeout)
                elif test_protocol == 'dot':
                    resp = dns.query.tls(q, resolver, timeout=self.args.timeout)
                elif test_protocol == 'doh':
                    resp = dns.query.https(q, resolver, timeout=self.args.timeout, client=self.httpx_client)

                # Check NXDOMAIN Hijack
                if len(resp.answer) > 0:
                    print(f"  {Fore.RED}[MISCONFIG] NXDOMAIN Hijacking Detected!{Style.RESET_ALL} (Non-existent domains resolve to {resp.answer[0].to_text()})")
                else:
                    print(f"  {Fore.GREEN}[OK] No NXDOMAIN Hijacking.{Style.RESET_ALL}")

                # Check Open Resolver
                if resp.flags & dns.flags.RA:
                    if resolver not in self.public_resolvers.values():
                        print(f"  {Fore.YELLOW}[WARNING] Recursion Available (RA) flag set. If this is a public IP, it's an OPEN RESOLVER!{Style.RESET_ALL}")
            except Exception as e:
                print(f"  {Fore.RED}[ERROR] Basic misconfig check failed: {e}{Style.RESET_ALL}")

            # 2. ECS (EDNS Client Subnet) Leak Check (Data Bleed)
            q_ecs = dns.message.make_query("o-o.myaddr.l.google.com", "TXT")
            try:
                if test_protocol == 'udp':
                    resp_ecs = dns.query.udp(q_ecs, resolver, timeout=self.args.timeout)
                elif test_protocol == 'tcp':
                    resp_ecs = dns.query.tcp(q_ecs, resolver, timeout=self.args.timeout)
                elif test_protocol == 'dot':
                    resp_ecs = dns.query.tls(q_ecs, resolver, timeout=self.args.timeout)
                elif test_protocol == 'doh':
                    resp_ecs = dns.query.https(q_ecs, resolver, timeout=self.args.timeout, client=self.httpx_client)

                ecs_leaked = False
                for answer in resp_ecs.answer:
                    for item in answer:
                        txt = item.to_text().strip('"')
                        if "edns0-client-subnet" in txt or "client-subnet" in txt:
                            ecs_leaked = True
                            print(f"  {Fore.RED}[BLEED] EDNS Client Subnet (ECS) Leak!{Style.RESET_ALL} Resolver leaks your subnet to authoritative servers: {txt}")
                if not ecs_leaked:
                    print(f"  {Fore.GREEN}[OK] No ECS Leak detected (High Privacy).{Style.RESET_ALL}")
            except Exception as e:
                pass

    def export_results(self, results):
        if 'json' in self.args.format:
            with open(f"{self.args.output}.json", "w") as f:
                json.dump(results, f, indent=2)
            print(f"Exported raw data to {self.args.output}.json")

        if 'csv' in self.args.format:
            with open(f"{self.args.output}.csv", "w", newline='') as f:
                if results:
                    writer = csv.DictWriter(f, fieldnames=results[0].keys())
                    writer.writeheader()
                    writer.writerows(results)
            print(f"Exported raw data to {self.args.output}.csv")

        if 'html' in self.args.format and PLOTLY_AVAILABLE:
            success_results = [r for r in results if r['latency_ms'] is not None]
            try:
                fig = px.box(success_results, x="resolver", y="latency_ms", color="protocol",
                             title="DNS Resolver Latency Distributions",
                             points="all")
                fig.write_html(f"{self.args.output}.html")
                print(f"Exported visualization to {self.args.output}.html")
            except Exception as e:
                print(f"{Fore.RED}[!] Could not generate HTML report: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="dnsbleed - DNS Response Timing Analyzer")
    parser.add_argument("-d", "--domains", type=str, required=True, help="Comma-separated domains to query")
    parser.add_argument("-r", "--resolvers", type=str, required=True, help="Comma-separated resolvers (IP or URL)")
    parser.add_argument("-c", "--count", type=int, default=50, help="Number of queries per resolver (default: 50)")
    parser.add_argument("-p", "--protocols", type=str, default="udp", help="Comma-separated protocols (udp, tcp, dot, doh)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=float, default=2.0, help="Query timeout in seconds")
    parser.add_argument("--jitter", type=float, default=0.0, help="Max random jitter between queries in seconds")
    parser.add_argument("--random-subdomains", action="store_true", help="Prefix queries with random subdomains to bypass cache")
    parser.add_argument("--cache-snoop", action="store_true", help="Enable cache snooping to bleed info on recently visited domains")
    parser.add_argument("--check-misconfigs", action="store_true", help="Check for NXDOMAIN hijacking, Open Resolver status, and ECS leaks")
    parser.add_argument("--proxy", type=str, default=None, help="Proxy URL (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument("-o", "--output", type=str, default="dnsbleed_report", help="Output file base name")
    parser.add_argument("-f", "--format", type=str, default="csv,json,html", help="Comma-separated output formats")

    args = parser.parse_args()

    if args.cache_snoop and args.random_subdomains:
        parser.error("--cache-snoop and --random-subdomains are mutually exclusive.")

    args.domains = [x.strip() for x in args.domains.split(",")]
    args.resolvers = [x.strip() for x in args.resolvers.split(",")]
    args.protocols = [x.strip() for x in args.protocols.split(",")]
    args.format = [x.strip() for x in args.format.split(",")]

    analyzer = DNSBleed(args)
    analyzer.run_tests()

if __name__ == "__main__":
    main()
