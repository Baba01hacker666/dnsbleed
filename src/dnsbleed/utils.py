import string
import random
try:
    import socks
except ImportError:
    pass

def parse_proxy(proxy_str):
    if proxy_str.startswith('socks5://'):
        return socks.SOCKS5, proxy_str[9:]
    elif proxy_str.startswith('socks4://'):
        return socks.SOCKS4, proxy_str[9:]
    elif proxy_str.startswith('http://'):
        return socks.HTTP, proxy_str[7:]
    return None, None

def generate_random_subdomain(domain):
    rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{rand_str}.{domain}"
