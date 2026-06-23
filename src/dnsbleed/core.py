import time
import socket
import dns.message
import dns.query
import dns.rdatatype
import httpx
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from dnsbleed.utils import parse_proxy, generate_random_subdomain

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

class DNSScanner:
    def __init__(self, resolvers, domains, protocols, count, threads, timeout, jitter, random_subdomains, proxy, qtypes=None):
        self.resolvers = resolvers
        self.domains = domains
        self.protocols = protocols
        self.count = count
        self.threads = threads
        self.timeout = timeout
        self.jitter = jitter
        self.random_subdomains = random_subdomains
        self.qtypes = qtypes or ["A"]
        
        self.httpx_client = None
        if proxy:
            if SOCKS_AVAILABLE:
                proxy_type, proxy_addr = parse_proxy(proxy)
                if proxy_type and proxy_addr:
                    host, port = proxy_addr.split(':')
                    socks.set_default_proxy(proxy_type, host, int(port))
                    socket.socket = socks.socksocket
            self.httpx_client = httpx.Client(proxy=proxy)

    def measure_query(self, resolver, domain, qtype, protocol, want_dnssec=False):
        qname = generate_random_subdomain(domain) if self.random_subdomains else domain
        
        # Determine the numeric query type from string
        try:
            rdtype = dns.rdatatype.from_text(qtype)
        except Exception:
            rdtype = dns.rdatatype.A
            
        q = dns.message.make_query(qname, rdtype)
        if want_dnssec:
            q.want_dnssec(True)
        else:
            q.use_edns(edns=0, payload=1232)
        
        if self.jitter > 0:
            time.sleep(random.uniform(0, self.jitter))
            
        start = time.perf_counter_ns()
        try:
            if protocol == 'udp':
                resp = dns.query.udp(q, resolver, timeout=self.timeout)
            elif protocol == 'tcp':
                resp = dns.query.tcp(q, resolver, timeout=self.timeout)
            elif protocol == 'dot':
                resp = dns.query.tls(q, resolver, timeout=self.timeout)
            elif protocol == 'doh':
                resp = dns.query.https(q, resolver, timeout=self.timeout, client=self.httpx_client)
            else:
                return None, "Unknown protocol"
            end = time.perf_counter_ns()
            latency_ms = (end - start) / 1e6
            return latency_ms, None
        except Exception as e:
            return None, str(e)

    def measure_query_task(self, resolver, domain, qtype, protocol, iteration):
        latency, err = self.measure_query(resolver, domain, qtype, protocol)
        return {
            "resolver": resolver,
            "domain": domain,
            "qtype": qtype,
            "protocol": protocol,
            "iteration": iteration,
            "latency_ms": latency,
            "error": err
        }

    def run_tests(self):
        results = []
        tasks = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for resolver in self.resolvers:
                for protocol in self.protocols:
                    for domain in self.domains:
                        for qtype in self.qtypes:
                            for i in range(self.count):
                                tasks.append(
                                    executor.submit(
                                        self.measure_query_task, resolver, domain, qtype, protocol, i
                                    )
                                )
                            
            with tqdm(total=len(tasks), desc="Querying", unit="req") as pbar:
                for future in as_completed(tasks):
                    res = future.result()
                    if res:
                        results.append(res)
                    pbar.update(1)
        return results
