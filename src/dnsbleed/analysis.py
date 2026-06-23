import statistics
import dns.message
import dns.query
import random
import string
from colorama import Fore, Style
from collections import defaultdict

PUBLIC_RESOLVERS = {
    "Google (8.8.8.8)": "8.8.8.8",
    "Cloudflare (1.1.1.1)": "1.1.1.1",
    "Quad9 (9.9.9.9)": "9.9.9.9",
    "OpenDNS (208.67.222.222)": "208.67.222.222"
}

def print_statistics(success_results):
    grouped = defaultdict(list)
    for r in success_results:
        grouped[(r['resolver'], r['protocol'])].append(r['latency_ms'])
        
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

    return grouped

def detect_cache_bleed(grouped):
    print(f"\n{Fore.RED}[!] Executing Cache Snooping (Data Bleed) Analysis...{Style.RESET_ALL}")
    for (res, prot), lats in grouped.items():
        if len(lats) < 3:
            continue
        
        first_query_lat = lats[0]
        cached_lats = lats[1:]
        cached_median = statistics.median(cached_lats)
        
        diff = first_query_lat - cached_median
        if diff < 5.0 and cached_median < 20.0:
            print(f"{Fore.MAGENTA}[BLEED] {res} ({prot}) -> Domain was LIKELY ALREADY CACHED (Someone visited it recently!){Style.RESET_ALL}")
        elif diff >= 5.0:
            print(f"{Fore.CYAN}[SECURE] {res} ({prot}) -> Domain was NOT cached (Latency drop: {diff:.2f}ms after first query){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[INCONCLUSIVE] {res} ({prot}) -> Timing delta too small or latency too high to determine cache status.{Style.RESET_ALL}")

def detect_leaks(grouped):
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

def check_misconfigs(resolvers, protocols, timeout, httpx_client):
    print(f"\n{Fore.MAGENTA}[*] Running DNS Misconfiguration & Privacy Checks...{Style.RESET_ALL}")
    for resolver in resolvers:
        print(f"\n{Fore.CYAN}Target Resolver: {resolver}{Style.RESET_ALL}")
        
        test_protocol = 'udp'
        if resolver.startswith("http"):
            test_protocol = 'doh'
        elif 'dot' in protocols:
            test_protocol = 'dot'
        elif 'tcp' in protocols:
            test_protocol = 'tcp'
        
        # 1. NXDOMAIN Hijacking & Open Resolver Check
        bad_domain = f"{''.join(random.choices(string.ascii_lowercase, k=15))}.com"
        q = dns.message.make_query(bad_domain, "A")
        try:
            if test_protocol == 'udp':
                resp = dns.query.udp(q, resolver, timeout=timeout)
            elif test_protocol == 'tcp':
                resp = dns.query.tcp(q, resolver, timeout=timeout)
            elif test_protocol == 'dot':
                resp = dns.query.tls(q, resolver, timeout=timeout)
            elif test_protocol == 'doh':
                resp = dns.query.https(q, resolver, timeout=timeout, client=httpx_client)
            
            # Check NXDOMAIN Hijack
            if len(resp.answer) > 0:
                print(f"  {Fore.RED}[MISCONFIG] NXDOMAIN Hijacking Detected!{Style.RESET_ALL} (Non-existent domains resolve to {resp.answer[0].to_text()})")
            else:
                print(f"  {Fore.GREEN}[OK] No NXDOMAIN Hijacking.{Style.RESET_ALL}")
                
            # Check Open Resolver
            if resp.flags & dns.flags.RA:
                if resolver not in PUBLIC_RESOLVERS.values():
                    print(f"  {Fore.YELLOW}[WARNING] Recursion Available (RA) flag set. If this is a public IP, it's an OPEN RESOLVER!{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.RED}[ERROR] Basic misconfig check failed: {e}{Style.RESET_ALL}")

        # 2. ECS (EDNS Client Subnet) Leak Check (Data Bleed)
        q_ecs = dns.message.make_query("o-o.myaddr.l.google.com", "TXT")
        try:
            if test_protocol == 'udp':
                resp_ecs = dns.query.udp(q_ecs, resolver, timeout=timeout)
            elif test_protocol == 'tcp':
                resp_ecs = dns.query.tcp(q_ecs, resolver, timeout=timeout)
            elif test_protocol == 'dot':
                resp_ecs = dns.query.tls(q_ecs, resolver, timeout=timeout)
            elif test_protocol == 'doh':
                resp_ecs = dns.query.https(q_ecs, resolver, timeout=timeout, client=httpx_client)
                
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

def check_dnssec(resolvers, protocols, timeout, httpx_client):
    print(f"\n{Fore.MAGENTA}[*] Running DNSSEC Validation Checks...{Style.RESET_ALL}")
    for resolver in resolvers:
        print(f"\n{Fore.CYAN}Target Resolver: {resolver}{Style.RESET_ALL}")
        
        test_protocol = 'udp'
        if resolver.startswith("http"):
            test_protocol = 'doh'
        elif 'dot' in protocols:
            test_protocol = 'dot'
        elif 'tcp' in protocols:
            test_protocol = 'tcp'
            
        # 1. Query standard DNSSEC signed domain with DO flag
        q_ad = dns.message.make_query("cloudflare.com", "A")
        q_ad.want_dnssec(True)
        
        # 2. Query bad signature domain (expect SERVFAIL if validating)
        q_fail = dns.message.make_query("dnssec-failed.org", "A")
        q_fail.want_dnssec(True)
        
        try:
            if test_protocol == 'udp':
                resp_ad = dns.query.udp(q_ad, resolver, timeout=timeout)
            elif test_protocol == 'tcp':
                resp_ad = dns.query.tcp(q_ad, resolver, timeout=timeout)
            elif test_protocol == 'dot':
                resp_ad = dns.query.tls(q_ad, resolver, timeout=timeout)
            elif test_protocol == 'doh':
                resp_ad = dns.query.https(q_ad, resolver, timeout=timeout, client=httpx_client)
                
            has_ad = bool(resp_ad.flags & dns.flags.AD)
            has_rrsig = any(rr.rdtype == dns.rdatatype.RRSIG for rr in resp_ad.answer) if hasattr(resp_ad, 'answer') else False
            
            if has_ad:
                print(f"  {Fore.GREEN}[OK] AD (Authentic Data) Flag Set.{Style.RESET_ALL} Resolver confirms DNSSEC cryptographic validity.")
            else:
                print(f"  {Fore.YELLOW}[WARNING] AD Flag NOT Set.{Style.RESET_ALL} Resolver does not indicate validation in header flags.")
                
            if has_rrsig:
                print(f"  {Fore.GREEN}[OK] DNSSEC RRSIG Signatures Received.{Style.RESET_ALL}")
            else:
                print(f"  {Fore.YELLOW}[WARNING] No DNSSEC RRSIG Signatures received in answer.{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.RED}[ERROR] DNSSEC Signed Domain Query failed: {e}{Style.RESET_ALL}")
            
        try:
            if test_protocol == 'udp':
                resp_fail = dns.query.udp(q_fail, resolver, timeout=timeout)
            elif test_protocol == 'tcp':
                resp_fail = dns.query.tcp(q_fail, resolver, timeout=timeout)
            elif test_protocol == 'dot':
                resp_fail = dns.query.tls(q_fail, resolver, timeout=timeout)
            elif test_protocol == 'doh':
                resp_fail = dns.query.https(q_fail, resolver, timeout=timeout, client=httpx_client)
                
            rcode = resp_fail.rcode()
            if rcode == dns.rcode.SERVFAIL:
                print(f"  {Fore.GREEN}[OK] DNSSEC Enforced correctly.{Style.RESET_ALL} Blocked invalid signature domain 'dnssec-failed.org' (RCODE: SERVFAIL).")
            elif rcode == dns.rcode.NOERROR:
                print(f"  {Fore.RED}[BLEED] DNSSEC Validation NOT Enforced!{Style.RESET_ALL} Allowed domain with invalid signatures 'dnssec-failed.org' (RCODE: NOERROR).")
            else:
                print(f"  {Fore.YELLOW}[INFO] Unexpected RCODE for invalid signature domain: {dns.rcode.to_text(rcode)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.YELLOW}[INFO] Invalid signature query failed/blocked: {e}{Style.RESET_ALL}")

def check_rate_limit(resolvers, protocols, timeout, httpx_client):
    print(f"\n{Fore.MAGENTA}[*] Running Rate-Limiting & Burst Resilience Checks...{Style.RESET_ALL}")
    for resolver in resolvers:
        print(f"\n{Fore.CYAN}Target Resolver: {resolver}{Style.RESET_ALL}")
        test_protocol = 'udp'
        if resolver.startswith("http"):
            test_protocol = 'doh'
        elif 'dot' in protocols:
            test_protocol = 'dot'
        elif 'tcp' in protocols:
            test_protocol = 'tcp'
            
        burst_count = 20
        failed = 0
        
        q = dns.message.make_query(f"{''.join(random.choices(string.ascii_lowercase, k=8))}.com", "A")
        
        for _ in range(burst_count):
            try:
                if test_protocol == 'udp':
                    dns.query.udp(q, resolver, timeout=0.5)
                elif test_protocol == 'tcp':
                    dns.query.tcp(q, resolver, timeout=0.5)
                elif test_protocol == 'dot':
                    dns.query.tls(q, resolver, timeout=0.5)
                elif test_protocol == 'doh':
                    dns.query.https(q, resolver, timeout=0.5, client=httpx_client)
            except Exception:
                failed += 1
                
        loss_rate = (failed / burst_count) * 100
        if loss_rate > 20.0:
            print(f"  {Fore.RED}[WARNING] High request loss under burst load!{Style.RESET_ALL} Loss rate: {loss_rate:.1f}% ({failed}/{burst_count} dropped). Resolver may be rate-limiting (RRL).")
        else:
            print(f"  {Fore.GREEN}[OK] Resolver resilient to quick burst.{Style.RESET_ALL} Loss rate: {loss_rate:.1f}% ({failed}/{burst_count} dropped).")
