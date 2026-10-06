"""Subdomain enumeration."""
import asyncio, re
try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False
try:
    import aiohttp
    AIO_OK = True
except ImportError:
    AIO_OK = False

COMMON_SUBS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "cpanel", "whm", "test", "dev", "blog", "admin", "forum",
    "vpn", "mail2", "mysql", "old", "support", "mobile", "mx",
    "static", "docs", "beta", "shop", "sql", "secure", "demo",
    "wiki", "web", "media", "images", "portal", "video", "sip",
    "api", "cdn", "stats", "search", "staging", "server", "chat",
    "svn", "proxy", "crm", "cms", "backup", "info", "apps",
    "download", "remote", "db", "store", "files", "app", "live",
    "owa", "office", "exchange", "start", "sms",
]

async def crt_sh_subdomains(domain):
    if not AIO_OK:
        return set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    out = set()
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
            async with s.get(url, ssl=False) as r:
                if r.status != 200:
                    return out
                data = await r.json(content_type=None)
                for e in data:
                    for line in (e.get("name_value") or "").split("\n"):
                        name = line.strip().lower().lstrip("*.")
                        if name.endswith("." + domain) or name == domain:
                            out.add(name)
    except Exception:
        pass
    return out

def _resolve(name):
    if not DNS_OK:
        return False
    try:
        dns.resolver.resolve(name, "A", lifetime=3)
        return True
    except Exception:
        try:
            dns.resolver.resolve(name, "AAAA", lifetime=3)
            return True
        except Exception:
            return False

def _resolve_ips(name):
    """Return set of A/AAAA IPs, empty if NXDOMAIN."""
    if not DNS_OK:
        return set()
    ips = set()
    for rtype in ("A", "AAAA"):
        try:
            for r in dns.resolver.resolve(name, rtype, lifetime=3):
                ips.add(str(r))
        except Exception:
            pass
    return ips


async def enumerate_subdomains(domain, use_crt=True):
    """Enumerate subdomains with wildcard DNS detection.

    A subdomain is only kept if it resolves to an IP that is NOT shared
    with a randomly-generated name. This kills wildcard DNS false positives.
    """
    loop = asyncio.get_event_loop()

    # 1. Detect wildcard by resolving two random names
    import random, string
    def _rand(n=20):
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    wildcard_ips: set = set()
    for _ in range(2):
        rname = f"{_rand()}.{domain}"
        ips = await loop.run_in_executor(None, _resolve_ips, rname)
        wildcard_ips |= ips

    is_wildcard = bool(wildcard_ips)

    # 2. Baseline IPs for the apex + www
    apex_ips = await loop.run_in_executor(None, _resolve_ips, domain)
    www_ips = await loop.run_in_executor(None, _resolve_ips, f"www.{domain}")
    shared_ips = wildcard_ips | apex_ips | www_ips

    # 3. Enumerate
    found = set()
    async def check(sub):
        fqdn = f"{sub}.{domain}"
        ips = await loop.run_in_executor(None, _resolve_ips, fqdn)
        if not ips:
            return None
        # If wildcard and this IP matches wildcard/apex/www, reject
        if is_wildcard and (ips & shared_ips):
            return None
        return fqdn

    results = await asyncio.gather(*(check(s) for s in COMMON_SUBS))
    for r in results:
        if r:
            found.add(r)

    # 4. crt.sh entries: verify each still resolves and is not wildcard
    if use_crt:
        crt = await crt_sh_subdomains(domain)
        for name in crt:
            if name in found:
                continue
            ips = await loop.run_in_executor(None, _resolve_ips, name)
            if not ips:
                continue
            if is_wildcard and (ips & shared_ips):
                continue
            found.add(name)

    return sorted(found)
