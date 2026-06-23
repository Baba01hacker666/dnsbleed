#!/usr/bin/env python3
import argparse
import sys
from colorama import init, Fore, Style

from dnsbleed.core import DNSScanner
from dnsbleed.analysis import (
    print_statistics,
    detect_cache_bleed,
    detect_leaks,
    check_misconfigs,
    check_dnssec,
    check_rate_limit
)
from dnsbleed.reporting import export_results

init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(description="dnsbleed - DNS Response Timing Analyzer")
    parser.add_argument("-d", "--domains", type=str, help="Comma-separated domains to query")
    parser.add_argument("-D", "--domains-file", type=str, help="File containing list of domains (one per line)")
    parser.add_argument("-r", "--resolvers", type=str, help="Comma-separated resolvers (IP or URL)")
    parser.add_argument("-R", "--resolvers-file", type=str, help="File containing list of resolvers (one per line)")
    parser.add_argument("-c", "--count", type=int, default=50, help="Number of queries per resolver (default: 50)")
    parser.add_argument("-p", "--protocols", type=str, default="udp", help="Comma-separated protocols (udp, tcp, dot, doh)")
    parser.add_argument("-q", "--qtypes", type=str, default="A", help="Comma-separated query types to use (default: A)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=float, default=2.0, help="Query timeout in seconds")
    parser.add_argument("--jitter", type=float, default=0.0, help="Max random jitter between queries in seconds")
    parser.add_argument("--random-subdomains", action="store_true", help="Prefix queries with random subdomains to bypass cache")
    parser.add_argument("--cache-snoop", action="store_true", help="Enable cache snooping to bleed info on recently visited domains")
    parser.add_argument("--check-misconfigs", action="store_true", help="Check for NXDOMAIN hijacking, Open Resolver status, and ECS leaks")
    parser.add_argument("--check-dnssec", action="store_true", help="Perform DNSSEC validation tests")
    parser.add_argument("--check-rate-limit", action="store_true", help="Detect resolver rate-limiting under burst query load")
    parser.add_argument("--proxy", type=str, default=None, help="Proxy URL (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument("-o", "--output", type=str, default="dnsbleed_report", help="Output file base name")
    parser.add_argument("-f", "--format", type=str, default="csv,json,html", help="Comma-separated output formats")
    
    args = parser.parse_args()
    
    if args.cache_snoop and args.random_subdomains:
        parser.error("--cache-snoop and --random-subdomains are mutually exclusive.")
        
    if not args.domains and not args.domains_file:
        parser.error("You must specify either --domains or --domains-file")
    if not args.resolvers and not args.resolvers_file:
        parser.error("You must specify either --resolvers or --resolvers-file")
        
    domains_list = []
    if args.domains:
        domains_list.extend([x.strip() for x in args.domains.split(",")])
    if args.domains_file:
        try:
            with open(args.domains_file, 'r') as f:
                domains_list.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            parser.error(f"Could not read domains file: {e}")
    domains = list(set(domains_list))
    
    resolvers_list = []
    if args.resolvers:
        resolvers_list.extend([x.strip() for x in args.resolvers.split(",")])
    if args.resolvers_file:
        try:
            with open(args.resolvers_file, 'r') as f:
                resolvers_list.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            parser.error(f"Could not read resolvers file: {e}")
    resolvers = list(set(resolvers_list))
    
    protocols = [x.strip() for x in args.protocols.split(",")]
    qtypes = [x.strip().upper() for x in args.qtypes.split(",")]
    formats = [x.strip() for x in args.format.split(",")]
    
    try:
        if args.proxy:
            print(f"{Fore.YELLOW}[*] Using proxy: {args.proxy}{Style.RESET_ALL}")
            
        print(f"{Fore.CYAN}[*] Starting DNS Response Timing Analyzer...{Style.RESET_ALL}")
        print(f"Resolvers: {', '.join(resolvers)}")
        print(f"Domains: {', '.join(domains)}")
        print(f"Protocols: {', '.join(protocols)}")
        print(f"Query Types: {', '.join(qtypes)}")
        print(f"Iterations: {args.count}\n")
        
        scanner = DNSScanner(
            resolvers=resolvers,
            domains=domains,
            protocols=protocols,
            count=args.count,
            threads=args.threads,
            timeout=args.timeout,
            jitter=args.jitter,
            random_subdomains=args.random_subdomains,
            proxy=args.proxy,
            qtypes=qtypes
        )
        
        results = scanner.run_tests()
        
        print(f"\n\n{Fore.GREEN}[*] Analysis Complete. Computing Statistics...{Style.RESET_ALL}\n")
        if not results:
            print(f"{Fore.RED}[!] No results gathered.{Style.RESET_ALL}")
            sys.exit(0)
            
        success_results = [r for r in results if r['latency_ms'] is not None]
        success_results.sort(key=lambda x: x['iteration'])
        
        grouped = print_statistics(success_results)
        
        if args.cache_snoop:
            detect_cache_bleed(grouped)
        else:
            detect_leaks(grouped)
            
        if args.check_misconfigs:
            check_misconfigs(resolvers, protocols, args.timeout, scanner.httpx_client)
            
        if args.check_dnssec:
            check_dnssec(resolvers, protocols, args.timeout, scanner.httpx_client)
            
        if args.check_rate_limit:
            check_rate_limit(resolvers, protocols, args.timeout, scanner.httpx_client)
            
        export_results(results, formats, args.output)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Execution interrupted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
