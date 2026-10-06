#!/usr/bin/env python3
"""hunter — active vulnerability scanner on top of hunter_payloads."""
from __future__ import annotations
import argparse, asyncio, hashlib, json, re, sys, time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl

import aiohttp
from bs4 import BeautifulSoup

from hunter_payloads import (
    XSS_PAYLOADS, XSS_MARKERS,
    SQLI_ERROR, SQLI_UNION, SQLI_TIME, SQLI_STACKED, SQLI_ERRORS_RE,
    SSRF_PAYLOADS, SSRF_MARKERS,
    LFI_PAYLOADS, LFI_MARKERS,
    CMDI_PAYLOADS, CMDI_MARKERS,
    SSTI_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS, REDIRECT_MARKER,
    CRLF_PAYLOADS, CRLF_HEADER_NAME,
    XXE_PAYLOAD_LINUX, XXE_PAYLOAD_WINDOWS, XXE_PAYLOAD_OOB, XXE_MARKERS,
    NOSQL_PAYLOADS,
    GRAPHQL_INTROSPECTION,
)
from hunter_oob import OOBServer
from hunter_v3_dedup import dedup, vuln_class
from hunter_v3_content import PATHS as CONTENT_PATHS, INTERESTING_STATUS
from hunter_v3_waf import detect_waf
from hunter_v3_auth import AuthConfig, login as do_login
from hunter_v3_subdomain import enumerate_subdomains
from hunter_v3_sarif import to_sarif
from hunter_v2_ext import (
    JS_CONTEXT_XSS_PAYLOADS, JS_CONTEXT_MARKERS,
    WAF_EVASION_XSS,
    HEADER_INJECTION_POINTS, HEADER_INJECT_PAYLOADS,
    JSON_INJECT_FIELDS,
    WAF_SIGNATURES,
    BLIND_CMDI_TEMPLATES, BLIND_SSRF_TEMPLATES, BLIND_XSS_TEMPLATES,
)

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
NEUTRAL = "WEBPT9F3APROBE"


@dataclass
class Hit:
    family: str
    url: str
    param: str
    method: str
    payload: str
    evidence: str
    confidence: str
    severity: str = "info"
    request_raw: str = ""
    response_status: int = 0
    response_headers: str = ""
    response_body: str = ""
    oob: bool = False


@dataclass
class Report:
    target: str
    started: str
    finished: str
    endpoints: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    hits: List[Hit] = field(default_factory=list)
    oob_hits: List[Dict] = field(default_factory=list)
    family_stats: Dict[str, Dict[str, int]] = field(default_factory=dict)
    waf: str = ""
    waf_confidence: float = 0.0
    discovered: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    auth_ok: bool = False
    auth_notes: List[str] = field(default_factory=list)
    raw_hits: int = 0
    summary: str = ""


class Client:
    def __init__(self, concurrency=12, cookies="", headers=None,
                 timeout=15.0, proxy=""):
        self.sem = asyncio.Semaphore(concurrency)
        self.session = None
        self.cookies_str = cookies
        self.headers = {"User-Agent": UA, "Accept": "*/*"}
        if headers:
            self.headers.update(headers)
        self.timeout = timeout
        self.proxy = proxy

    async def __aenter__(self):
        jar = aiohttp.CookieJar(unsafe=True)
        to = aiohttp.ClientTimeout(total=self.timeout, connect=7, sock_read=12)
        conn = aiohttp.TCPConnector(limit=64, ssl=False, enable_cleanup_closed=True)
        self.session = aiohttp.ClientSession(timeout=to, connector=conn, cookie_jar=jar)
        return self

    async def __aexit__(self, *a):
        if self.session:
            await self.session.close()

    async def req(self, method, url, params=None, data=None,
                  extra_headers=None, allow_redirects=True):
        async with self.sem:
            hdrs = dict(self.headers)
            if extra_headers:
                hdrs.update(extra_headers)
            if self.cookies_str:
                hdrs.setdefault("Cookie", self.cookies_str)
            t0 = time.monotonic()
            try:
                kw = {"headers": hdrs, "allow_redirects": allow_redirects, "ssl": False}
                if self.proxy:
                    kw["proxy"] = self.proxy
                if method == "GET":
                    kw["params"] = params or {}
                else:
                    if data is not None:
                        kw["data"] = data
                    elif params:
                        kw["data"] = urlencode(params).encode()
                async with self.session.request(method, url, **kw) as r:
                    body = await r.read()
                    hdr = {k.lower(): v for k, v in r.headers.items()}
                    return r.status, hdr, body, int((time.monotonic()-t0)*1000)
            except Exception as e:
                return 0, {"error": str(e)}, b"", int((time.monotonic()-t0)*1000)


ROBOTS_LINE_RE = re.compile(r"(?:Disallow|Allow|Sitemap):\s*(\S+)", re.I)


async def fetch_robots(c, base):
    url = urljoin(base, "/robots.txt")
    s, h, b, _ = await c.req("GET", url)
    if s != 200:
        return []
    out = []
    for line in b.decode("utf-8", errors="ignore").splitlines():
        m = ROBOTS_LINE_RE.match(line.strip())
        if not m:
            continue
        v = m.group(1)
        if v.startswith("http"):
            out.append(v)
        elif v.startswith("/"):
            out.append(urljoin(base, v))
    return out


async def fetch_sitemap(c, sitemap_url):
    s, h, b, _ = await c.req("GET", sitemap_url)
    if s != 200:
        return []
    text = b.decode("utf-8", errors="ignore")
    locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I)
    if not locs:
        return []
    if any(u.endswith(".xml") for u in locs[:3]):
        nested = []
        for u in locs[:10]:
            try:
                nested.extend(await fetch_sitemap(c, u))
            except Exception:
                pass
        return nested
    return locs


JS_PATH_RES = [
    re.compile(r'"(/api/[^"\s<>]+)"'),
    re.compile(r'"(/v\d+/[^"\s<>]+)"'),
    re.compile(r'"(/admin[^"\s<>]*)"'),
    re.compile(r'"(/user[^"\s<>]*)"'),
    re.compile(r'"(/auth[^"\s<>]*)"'),
    re.compile(r'"(/login[^"\s<>]*)"'),
    re.compile(r'"(/upload[^"\s<>]*)"'),
    re.compile(r'"(/search[^"\s<>]*)"'),
    re.compile(r'"(/download[^"\s<>]*)"'),
    re.compile(r'"(/file[^"\s<>]*)"'),
]


def extract_js_paths(text):
    paths = set()
    for rx in JS_PATH_RES:
        for m in rx.finditer(text):
            v = m.group(1)
            if v.startswith("/"):
                paths.add(v)
    return sorted(paths)


async def crawl(c, base, depth):
    seen, queue, out = set(), [base], []
    host = urlparse(base).netloc

    try:
        for u in await fetch_robots(c, base):
            if urlparse(u).netloc in ("", host):
                queue.append(u)
    except Exception:
        pass

    try:
        for u in await fetch_sitemap(c, urljoin(base, "/sitemap.xml")):
            if urlparse(u).netloc in ("", host):
                queue.append(u)
    except Exception:
        pass

    while queue and len(out) < 500:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        s, h, b, _ = await c.req("GET", url)
        if s == 0:
            continue
        ctype = h.get("content-type", "")
        if "html" not in ctype and "xml" not in ctype and "json" not in ctype:
            continue
        out.append(url)
        if depth <= 0:
            continue
        try:
            soup = BeautifulSoup(b.decode("utf-8", errors="ignore"), "html.parser")
        except Exception:
            continue
        for tag in soup.find_all(["a", "form", "script", "link", "iframe"]):
            attr = tag.get("href") or tag.get("action") or tag.get("src")
            if not attr or attr.startswith(("mailto:", "javascript:", "tel:", "data:")):
                continue
            full = urljoin(url, attr)
            if urlparse(full).netloc == host and full not in seen:
                queue.append(full)

        # Link: response header
        link_header = h.get("link", "")
        for m in re.finditer(r"<([^>]+)>", link_header):
            cand = urljoin(url, m.group(1))
            if urlparse(cand).netloc == host and cand not in seen:
                queue.append(cand)

        # external scripts
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if not src:
                continue
            js_url = urljoin(url, src)
            if urlparse(js_url).netloc != host:
                continue
            try:
                js_s, js_h, js_b, _ = await c.req("GET", js_url)
                if js_s == 200:
                    for p in extract_js_paths(js_b.decode("utf-8", errors="ignore")):
                        queue.append(urljoin(url, p))
            except Exception:
                pass
    return out


async def extract_forms(c, url):
    _, _, body, _ = await c.req("GET", url)
    out = []
    try:
        soup = BeautifulSoup(body.decode("utf-8", errors="ignore"), "html.parser")
    except Exception:
        return out
    for f in soup.find_all("form"):
        action = urljoin(url, f.get("action") or url)
        method = (f.get("method") or "GET").upper()
        fields = {}
        for inp in f.find_all(["input", "textarea", "select"]):
            n = inp.get("name")
            if n:
                fields[n] = inp.get("value", "test")
        if fields:
            out.append((action, method, fields))
    return out


def _text(b):
    try:
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _reflected(marker, body, baseline):
    nt = _text(body)
    bt = _text(baseline)
    if marker not in nt or marker in bt:
        return None
    i = nt.find(marker)
    return nt[max(0, i - 40):i + len(marker) + 40]


def _regex_new(patterns, body, baseline):
    nt = _text(body)
    bt = _text(baseline)
    for rx in patterns:
        m = re.search(rx, nt)
        if not m:
            continue
        if re.search(rx, bt):
            continue
        return nt[max(0, m.start() - 30):m.end() + 30]
    return None


class Det:
    @staticmethod
    async def xss(c, url, method, param, baseline, other):
        for pl in XSS_PAYLOADS:
            p = dict(other); p[param] = pl
            s, h, b, _ = await c.req(method, url, params=p)
            for marker in XSS_MARKERS:
                ctx = _reflected(marker, b, baseline)
                if ctx is not None:
                    return Hit("xss", url, param, method, pl, ctx, "confirmed")
        return None

    @staticmethod
    async def xss_js(c, url, method, param, baseline, other):
        for pl in JS_CONTEXT_XSS_PAYLOADS:
            p = dict(other); p[param] = pl
            s, h, b, _ = await c.req(method, url, params=p)
            for marker in JS_CONTEXT_MARKERS:
                ctx = _reflected(marker, b, baseline)
                if ctx is not None:
                    return Hit("xss_js_context", url, param, method, pl, ctx, "confirmed")
        return None

    @staticmethod
    async def xss_waf_evasion(c, url, method, param, baseline, other):
        for pl in WAF_EVASION_XSS:
            p = dict(other); p[param] = pl
            s, h, b, _ = await c.req(method, url, params=p)
            for marker in XSS_MARKERS:
                ctx = _reflected(marker, b, baseline)
                if ctx is not None:
                    return Hit("xss_waf_evasion", url, param, method, pl, ctx, "confirmed")
        return None

    @staticmethod
    async def header_inject(c, url, method, fields, baseline):
        for hdr in HEADER_INJECTION_POINTS:
            for pl in HEADER_INJECT_PAYLOADS:
                s, h, b, _ = await c.req(
                    method, url,
                    params=fields if method == "GET" else None,
                    data=urlencode(fields).encode() if method != "GET" else None,
                    extra_headers={hdr: pl})
                for marker in XSS_MARKERS:
                    ctx = _reflected(marker, b, baseline)
                    if ctx is not None:
                        return Hit("header_inject", url, hdr, method, pl, ctx, "confirmed")
        return None

    @staticmethod
    async def json_body(c, url, baseline):
        for field in JSON_INJECT_FIELDS:
            for pl in ("<script>alert(1)</script>", "\"><script>alert(1)</script>",
                       "1;alert(1);var x='", "' OR 1=1--"):
                body = json.dumps({field: pl}).encode()
                s, h, b, _ = await c.req("POST", url, data=body,
                                         extra_headers={"Content-Type": "application/json"})
                for marker in XSS_MARKERS + JS_CONTEXT_MARKERS:
                    ctx = _reflected(marker, b, baseline)
                    if ctx is not None:
                        return Hit("json_xss", url, field, "POST", pl, ctx, "confirmed")
                for rx in SQLI_ERRORS_RE:
                    m = re.search(rx, _text(b))
                    if m and not re.search(rx, _text(baseline)):
                        ctx = _text(b)[max(0, m.start()-30):m.end()+30]
                        return Hit("json_sqli", url, field, "POST", pl, ctx, "confirmed")
        return None

    @staticmethod
    async def blind_cmdi(c, url, method, param, baseline, other, oob):
        if oob is None:
            return None
        cb = f"127.0.0.1:{oob.port}"
        for tpl in BLIND_CMDI_TEMPLATES:
            tok = f"cmdi{int(time.time()*1000) % 1000000}"
            pl = tpl.format(tok=tok, cb=cb, host=cb)
            p = dict(other); p[param] = pl
            await c.req(method, url, params=p)
        await asyncio.sleep(3)
        for h in oob.hits:
            path = h.get("path", "")
            if "cmdi" in path:
                return Hit("blind_cmdi", url, param, method, "OOB nslookup/curl",
                           f"callback: {path} from {h.get('client')}", "oob", oob=True)
        return None

    @staticmethod
    async def blind_ssrf(c, url, method, param, baseline, other, oob):
        if oob is None:
            return None
        cb = f"127.0.0.1:{oob.port}"
        for tpl in BLIND_SSRF_TEMPLATES:
            tok = f"ssrf{int(time.time()*1000) % 1000000}"
            pl = tpl.format(tok=tok, cb=cb)
            p = dict(other); p[param] = pl
            await c.req(method, url, params=p)
        await asyncio.sleep(3)
        for h in oob.hits:
            path = h.get("path", "")
            if "ssrf" in path:
                return Hit("blind_ssrf", url, param, method, "OOB URL",
                           f"callback: {path} from {h.get('client')}", "oob", oob=True)
        return None

    @staticmethod
    async def sqli(c, url, method, param, baseline_status, baseline, other):
        for pl in SQLI_ERROR:
            p = dict(other); p[param] = pl
            s, h, b, _ = await c.req(method, url, params=p)
            m = _regex_new(SQLI_ERRORS_RE, b, baseline)
            if m:
                return Hit("sqli_error", url, param, method, pl, m, "confirmed")

        for pl in SQLI_UNION:
            p = dict(other); p[param] = pl
            s, h, b, _ = await c.req(method, url, params=p)
            m = _regex_new(SQLI_ERRORS_RE, b, baseline)
            if m:
                return Hit("sqli_union", url, param, method, pl, m, "confirmed")

        pt = dict(other); pt[param] = "1' AND '1'='1"
        pf = dict(other); pf[param] = "1' AND '1'='2"
        s1, _, b1, _ = await c.req(method, url, params=pt)
        s2, _, b2, _ = await c.req(method, url, params=pf)
        if s1 == s2 == baseline_status and abs(len(b1) - len(b2)) > 20:
            return Hit("sqli_boolean", url, param, method,
                       "1' AND '1'='1 vs 1' AND '1'='2",
                       f"len diff {abs(len(b1)-len(b2))} bytes", "high")

        for pl in SQLI_TIME:
            p = dict(other); p[param] = pl
            s, _, _, ms = await c.req(method, url, params=p)
            if ms > 4500:
                s2, _, _, ms2 = await c.req(method, url, params=p)
                if ms2 > 4500:
                    return Hit("sqli_time", url, param, method, pl,
                               f"first={ms}ms second={ms2}ms", "confirmed")

        for pl in SQLI_STACKED:
            p = dict(other); p[param] = pl
            s, _, b, _ = await c.req(method, url, params=p)
            if s in (500, 502):
                m = _regex_new(SQLI_ERRORS_RE, b, baseline)
                if m:
                    return Hit("sqli_stacked", url, param, method, pl, m, "high")
        return None

    @staticmethod
    async def lfi(c, url, method, param, baseline, other):
        for pl in LFI_PAYLOADS:
            p = dict(other); p[param] = pl
            s, h, b, _ = await c.req(method, url, params=p)
            m = _regex_new(LFI_MARKERS, b, baseline)
            if m:
                return Hit("lfi", url, param, method, pl, m, "confirmed")
        return None

    @staticmethod
    async def cmdi(c, url, method, param, baseline, other):
        for pl in CMDI_PAYLOADS:
            p = dict(other); p[param] = pl
            s, h, b, ms = await c.req(method, url, params=p)
            m = _regex_new(CMDI_MARKERS, b, baseline)
            if m:
                return Hit("cmdi", url, param, method, pl, m, "confirmed")
            if "sleep 5" in pl and ms > 4500:
                s2, _, _, ms2 = await c.req(method, url, params=p)
                if ms2 > 4500:
                    return Hit("cmdi_time", url, param, method, pl,
                               f"{ms}ms / {ms2}ms", "confirmed")
        return None

    @staticmethod
    async def ssti(c, url, method, param, baseline, other):
        bt = _text(baseline)
        for pl, expected in SSTI_PAYLOADS:
            p = dict(other); p[param] = pl
            s, h, b, _ = await c.req(method, url, params=p)
            nt = _text(b)
            if expected and expected in nt and expected not in bt and pl not in nt:
                i = nt.find(expected)
                return Hit("ssti", url, param, method, pl,
                           f"{pl} -> {expected} : {nt[max(0,i-30):i+len(expected)+30]}",
                           "confirmed")
        return None

    @staticmethod
    async def redirect(c, url, method, param, other):
        for pl in OPEN_REDIRECT_PAYLOADS:
            p = dict(other); p[param] = pl
            s, h, b, _ = await c.req(method, url, params=p, allow_redirects=False)
            loc = h.get("location", "")
            if REDIRECT_MARKER in loc:
                return Hit("open_redirect", url, param, method, pl,
                           f"Location: {loc}", "confirmed")
        return None

    @staticmethod
    async def crlf(c, url, method, param, other):
        for pl in CRLF_PAYLOADS:
            p = dict(other); p[param] = pl
            s, h, b, _ = await c.req(method, url, params=p, allow_redirects=False)
            if CRLF_HEADER_NAME in h:
                return Hit("crlf", url, param, method, pl,
                           f"{CRLF_HEADER_NAME}: {h[CRLF_HEADER_NAME]}", "confirmed")
            if "webpt=crlf" in h.get("set-cookie", ""):
                return Hit("crlf", url, param, method, pl,
                           f"Set-Cookie: {h['set-cookie']}", "confirmed")
            if "evil.com" in h.get("location", ""):
                return Hit("crlf", url, param, method, pl,
                           f"Location: {h['location']}", "confirmed")
        return None

    @staticmethod
    async def ssrf(c, url, method, param, baseline, other):
        for pl in SSRF_PAYLOADS:
            p = dict(other); p[param] = pl
            s, h, b, _ = await c.req(method, url, params=p)
            nt = _text(b)
            bt = _text(baseline)
            for marker in SSRF_MARKERS:
                if marker in nt and marker not in bt and marker not in pl:
                    i = nt.find(marker)
                    return Hit("ssrf", url, param, method, pl,
                               nt[max(0, i-30):i+60], "high")
        return None

    @staticmethod
    async def nosql(c, url, method, param, baseline_status, other):
        for pl in NOSQL_PAYLOADS:
            p = dict(other); p[param] = pl
            if method == "POST":
                s, h, b, _ = await c.req(method, url, data=pl.encode(),
                                         extra_headers={"Content-Type": "application/json"})
            else:
                s, h, b, _ = await c.req(method, url, params=p)
            if s in (200, 302) and baseline_status in (401, 403):
                return Hit("nosql_auth_bypass", url, param, method, pl,
                           f"baseline={baseline_status} with_payload={s}", "high")
        return None

    @staticmethod
    async def xxe(c, url, baseline, oob):
        for payload in (XXE_PAYLOAD_LINUX, XXE_PAYLOAD_WINDOWS):
            s, h, b, _ = await c.req("POST", url, data=payload.encode(),
                                     extra_headers={"Content-Type": "application/xml"})
            m = _regex_new(XXE_MARKERS, b, baseline)
            if m:
                return Hit("xxe", url, "body", "POST", payload[:80] + "...", m, "confirmed")
        if oob is not None:
            marker = f"xxe-{int(time.time()*1000)}"
            oob_payload = XXE_PAYLOAD_OOB.replace("attacker.com",
                                                   f"127.0.0.1:{oob.port}")
            await c.req("POST", url, data=oob_payload.encode(),
                        extra_headers={"Content-Type": "application/xml"})
            await asyncio.sleep(3)
            if oob.marker_hit("xxe.dtd"):
                return Hit("xxe_oob", url, "body", "POST",
                           oob_payload[:80] + "...",
                           f"OOB callback: {marker}", "oob", oob=True)
        return None

    @staticmethod
    async def graphql(c, url):
        hits = []
        for pl in GRAPHQL_INTROSPECTION:
            s, h, b, _ = await c.req("POST", url, data=pl.encode(),
                                     extra_headers={"Content-Type": "application/json"})
            nt = _text(b)
            if "__schema" in nt and ("types" in nt or "kind" in nt):
                hits.append(Hit("graphql_introspection", url, "body", "POST",
                                pl, "introspection returned schema", "confirmed"))
                break
        return hits


def classify_severity(hit, authenticated=False):
    fam = hit.family
    url_low = hit.url.lower()
    ev_low = (hit.evidence or "").lower()

    if fam in ("cmdi", "cmdi_time", "ssti", "nosql_auth_bypass"):
        return "critical"
    if fam.startswith("sqli"):
        return "high"
    if fam == "lfi":
        return "high"
    if fam == "ssrf":
        if any(m in ev_low for m in ("security-credentials", "accesskeyid", "secretaccesskey")):
            return "critical"
        return "high"
    if fam in ("xxe", "xxe_oob"):
        return "high"
    if fam == "xss":
        ev = (hit.evidence or "")
        if "<script>" in ev and ("var " in ev or "eval" in ev):
            return "high"
        if authenticated:
            return "high"
        if any(k in url_low for k in ("/admin", "/api/", "/account", "/profile", "/settings", "/dashboard")):
            return "high"
        return "medium"
    if fam == "xss_js_context":
        return "high"
    if fam == "xss_waf_evasion":
        return "high"
    if fam in ("header_inject",):
        return "medium"
    if fam in ("json_xss", "json_sqli"):
        return "high"
    if fam == "blind_cmdi":
        return "critical"
    if fam == "blind_ssrf":
        return "high"
    if fam in ("crlf", "redirect", "open_redirect"):
        return "medium"
    if fam == "graphql_introspection":
        return "low"
    return "medium"


async def capture_proof(c, hit):
    parsed = urlparse(hit.url)
    path_q = parsed.path or "/"
    if hit.method == "GET":
        path_q = path_q + "?" + urlencode({hit.param: hit.payload})
    req_lines = [
        f"{hit.method} {path_q} HTTP/1.1",
        f"Host: {parsed.netloc}",
    ]
    for k, v in c.headers.items():
        if k.lower() == "host":
            continue
        req_lines.append(f"{k}: {v}")
    if c.cookies_str:
        req_lines.append(f"Cookie: {c.cookies_str}")

    try:
        if hit.method == "GET":
            status, hdrs, body, _ = await c.req("GET", hit.url,
                                                 params={hit.param: hit.payload})
        else:
            status, hdrs, body, _ = await c.req(hit.method, hit.url,
                                                 data=urlencode({hit.param: hit.payload}).encode())
    except Exception:
        return

    resp_lines = [f"HTTP/1.1 {status}"]
    for k, v in hdrs.items():
        if k == "error":
            continue
        resp_lines.append(f"{k}: {v}")

    hit.request_raw = "\n".join(req_lines) + "\n"
    hit.response_status = status
    hit.response_headers = "\n".join(resp_lines) + "\n"

    body_text = body.decode("utf-8", errors="ignore")
    snippet = ""
    if hit.evidence:
        key = hit.evidence.strip()[:60]
        idx = body_text.find(key)
        if idx >= 0:
            start = max(0, idx - 300)
            end = min(len(body_text), idx + 600)
            snippet = body_text[start:end]
    if not snippet:
        snippet = body_text[:800]
    hit.response_body = snippet


FAMILIES = ("xss", "xss_js", "xss_waf_evasion",
            "header_inject", "json_body",
            "blind_cmdi", "blind_ssrf",
            "sqli", "lfi", "cmdi", "ssti",
            "redirect", "crlf", "ssrf", "nosql", "graphql")


async def scan_param(c, url, method, param, fields, enabled, oob):
    other = {k: v for k, v in fields.items() if k != param}
    hits = []
    s0, h0, b0, _ = await c.req(method, url, params={**other, param: NEUTRAL})
    if s0 == 0:
        return hits

    jobs = []
    if "xss" in enabled:
        jobs.append(Det.xss(c, url, method, param, b0, other))
    if "xss_js" in enabled:
        jobs.append(Det.xss_js(c, url, method, param, b0, other))
    if "xss_waf_evasion" in enabled:
        jobs.append(Det.xss_waf_evasion(c, url, method, param, b0, other))
    if "blind_cmdi" in enabled:
        jobs.append(Det.blind_cmdi(c, url, method, param, b0, other, oob))
    if "blind_ssrf" in enabled:
        jobs.append(Det.blind_ssrf(c, url, method, param, b0, other, oob))
    if "sqli" in enabled:
        jobs.append(Det.sqli(c, url, method, param, s0, b0, other))
    if "lfi" in enabled:
        jobs.append(Det.lfi(c, url, method, param, b0, other))
    if "cmdi" in enabled:
        jobs.append(Det.cmdi(c, url, method, param, b0, other))
    if "ssti" in enabled:
        jobs.append(Det.ssti(c, url, method, param, b0, other))
    if "redirect" in enabled:
        jobs.append(Det.redirect(c, url, method, param, other))
    if "crlf" in enabled:
        jobs.append(Det.crlf(c, url, method, param, other))
    if "ssrf" in enabled:
        jobs.append(Det.ssrf(c, url, method, param, b0, other))
    if "nosql" in enabled:
        jobs.append(Det.nosql(c, url, method, param, s0, other))

    for j in jobs:
        try:
            r = await j
            if r:
                hits.append(r)
        except Exception:
            pass

    for h in hits:
        h.severity = classify_severity(h)
        try:
            await capture_proof(c, h)
        except Exception:
            pass
    return hits


async def run(target, args):
    rep = Report(target=target,
                 started=datetime.now(timezone.utc).isoformat(),
                 finished="")

    oob = None
    if not args.no_oob:
        oob = OOBServer(bind="0.0.0.0", port=args.oob_port).start()
        print(f"[*] OOB listener on :{oob.port}")

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    async with Client(concurrency=args.c, cookies=args.cookies,
                      headers=headers, proxy=args.proxy) as c:
        print(f"[*] Crawling {target} (depth={args.depth})")
        pages = await crawl(c, target, args.depth)
        rep.endpoints = pages
        print(f"[*] {len(pages)} pages")

        # ---- WAF detection
        try:
            s0, h0, b0, _ = await c.req("GET", target)
            waf_name, waf_conf = detect_waf(s0, h0, b0)
            rep.waf = waf_name
            rep.waf_confidence = waf_conf
            if waf_name:
                print(f"[*] WAF detected: {waf_name} ({waf_conf:.2f})")
        except Exception:
            pass

        # ---- auth login
        if args.auth_login:
            try:
                acfg = AuthConfig(
                    login_url=args.auth_login,
                    username=args.auth_user or "",
                    password=args.auth_pass or "",
                    csrf_meta=args.auth_csrf_meta,
                    success_marker=args.auth_success_marker,
                    verify_url=args.auth_verify,
                )
                ok, notes = await do_login(c, acfg)
                rep.auth_ok = ok
                rep.auth_notes = notes
                print(f"[*] Auth: {'OK' if ok else 'FAILED'}")
                for n in notes:
                    print(f"    {n}")
            except Exception as e:
                print(f"[!] auth error: {e}")

        # ---- content discovery
        if not args.no_content:
            print(f"[*] Content discovery ({len(CONTENT_PATHS)} paths)")
            for path in CONTENT_PATHS:
                full = urljoin(target, path)
                try:
                    st, hd, bd, _ = await c.req("GET", full, allow_redirects=False)
                    if st in INTERESTING_STATUS:
                        line = f"{st:4} {len(bd):7} {full}"
                        rep.discovered.append(line)
                except Exception:
                    continue
            print(f"[*] {len(rep.discovered)} interesting paths")

        targets = []
        for p in pages:
            qs = dict(parse_qsl(urlparse(p).query))
            if qs:
                targets.append(("GET", p, qs))
            for action, method, fields in await extract_forms(c, p):
                targets.append((method, action, fields))

        seen = set()
        uniq = []
        for m, u, f in targets:
            sig = f"{m}|{urlparse(u).path}|{','.join(sorted(f.keys()))}"
            if sig in seen:
                continue
            seen.add(sig)
            uniq.append((m, u, f))

        rep.params = sorted({k for _, _, f in uniq for k in f.keys()})
        print(f"[*] {len(uniq)} param-sets / {len(rep.params)} params")

        enabled = set(args.families) if args.families else set(FAMILIES)

        for method, url, fields in uniq:
            for param in list(fields.keys()):
                hits = await scan_param(c, url, method, param, fields, enabled, oob)
                for h in hits:
                    rep.hits.append(h)
                    print(f"[+] {h.family:22} {url} [{param}] -> {h.evidence[:80]}")

        # ---- header injection pass
        if "header_inject" in enabled:
            for method, url, fields in uniq[:30]:
                try:
                    s0, h0, b0, _ = await c.req(method, url,
                        params={**fields, "probe": NEUTRAL} if method == "GET" else None,
                        data=urlencode({**fields, "probe": NEUTRAL}).encode() if method != "GET" else None)
                    h = await Det.header_inject(c, url, method, fields, b0)
                    if h:
                        h.severity = classify_severity(h)
                        try:
                            await capture_proof(c, h)
                        except Exception:
                            pass
                        rep.hits.append(h)
                        print(f"[+] {h.family:22} {url} [{h.param}] -> {h.evidence[:80]}")
                except Exception:
                    continue

        # ---- JSON body pass
        if "json_body" in enabled:
            for method, url, fields in uniq[:30]:
                if method != "POST":
                    continue
                try:
                    s0, h0, b0, _ = await c.req("POST", url,
                        data=json.dumps({"probe": NEUTRAL}).encode(),
                        extra_headers={"Content-Type": "application/json"})
                    h = await Det.json_body(c, url, b0)
                    if h:
                        h.severity = classify_severity(h)
                        try:
                            await capture_proof(c, h)
                        except Exception:
                            pass
                        rep.hits.append(h)
                        print(f"[+] {h.family:22} {url} [{h.param}] -> {h.evidence[:80]}")
                except Exception:
                    continue

        # ---- XXE pass
        for method, url, fields in uniq:
            if method != "POST":
                continue
            try:
                h = await Det.xxe(c, url, b"", oob)
                if h:
                    h.severity = classify_severity(h)
                    rep.hits.append(h)
                    print(f"[+] {h.family:22} {url} -> {h.evidence[:80]}")
            except Exception:
                continue

        for path in ("/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/gql"):
            full = urljoin(target, path)
            try:
                for h in await Det.graphql(c, full):
                    rep.hits.append(h)
                    print(f"[+] {h.family:22} {full} -> {h.evidence[:80]}")
            except Exception:
                continue

        if oob is not None:
            rep.oob_hits = oob.hits
            oob.stop()

    # ---- subdomain enumeration (DNS + crt.sh) after HTTP session closes
    if not args.no_subs:
        try:
            domain = urlparse(target).netloc.split(":")[0]
            print(f"[*] Subdomain enumeration for {domain}")
            subs = await enumerate_subdomains(domain, use_crt=not args.no_crt)
            rep.subdomains = subs
            print(f"[*] {len(subs)} subdomains found")
        except Exception as e:
            print(f"[!] subdomain error: {e}")

    rep.raw_hits = len(rep.hits)
    rep.hits = dedup(rep.hits)

    stats = {}
    for f in set(FAMILIES) | {"xxe", "xxe_oob", "graphql_introspection",
                              "sqli_boolean", "sqli_union", "sqli_stacked",
                              "sqli_time", "cmdi_time", "nosql_auth_bypass"}:
        stats[f] = {"hits": 0}
    for h in rep.hits:
        stats.setdefault(h.family, {"hits": 0})
        stats[h.family]["hits"] += 1
    rep.family_stats = stats

    rep.finished = datetime.now(timezone.utc).isoformat()
    rep.summary = (f"target={target} endpoints={len(rep.endpoints)} "
                   f"params={len(rep.params)} "
                   f"raw_hits={rep.raw_hits} unique_hits={len(rep.hits)} "
                   f"waf={rep.waf or 'none'}")
    return rep


def render(rep):
    out = ["=" * 78,
           "hunter — active vulnerability scanner",
           f"target  : {rep.target}",
           f"started : {rep.started}",
           f"finished: {rep.finished}",
           "=" * 78, ""]
    out.append("## Summary")
    out.append("  " + rep.summary)
    out.append("")
    if rep.waf:
        out.append("## WAF / Edge")
        out.append(f"  detected   : {rep.waf}")
        out.append(f"  confidence : {rep.waf_confidence:.2f}")
        out.append("")
    if rep.auth_ok:
        out.append("## Authentication")
        out.append("  login      : OK")
        for n in rep.auth_notes:
            out.append(f"    {n}")
        out.append("")
    if rep.subdomains:
        out.append(f"## Subdomains ({len(rep.subdomains)})")
        for sub in rep.subdomains[:40]:
            out.append(f"  {sub}")
        out.append("")
    if rep.discovered:
        out.append(f"## Discovered paths ({len(rep.discovered)})")
        for line in rep.discovered[:80]:
            out.append(f"  {line}")
        out.append("")
    out.append("## Family statistics")
    for f, s in sorted(rep.family_stats.items()):
        out.append(f"  {f:24} hits={s['hits']}")
    out.append("")
    out.append(f"## Hits ({len(rep.hits)})")
    if not rep.hits:
        out.append("  (none)")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(rep.hits, key=lambda x: sev_order.get(x.severity, 9))
    for i, h in enumerate(ordered, 1):
        out.append(f"  [{i:03d}] [{h.severity.upper():8}] {h.family:22} confidence={h.confidence}")
        out.append(f"        url     : {h.url}")
        out.append(f"        param   : {h.param}  method={h.method}")
        out.append(f"        payload : {h.payload[:140]}")
        out.append(f"        evidence: {h.evidence[:180]}")
        if h.request_raw:
            out.append(f"        --- request ---")
            for line in h.request_raw.splitlines()[:10]:
                out.append(f"        {line[:180]}")
        if h.response_status:
            out.append(f"        --- response status={h.response_status} ---")
            if h.response_headers:
                for line in h.response_headers.splitlines()[:8]:
                    out.append(f"        {line[:180]}")
            if h.response_body:
                for line in h.response_body.splitlines()[:12]:
                    out.append(f"        {line[:180]}")
    if rep.oob_hits:
        out.append("")
        out.append(f"## OOB Callbacks ({len(rep.oob_hits)})")
        for i, o in enumerate(rep.oob_hits, 1):
            out.append(f"  [{i:03d}] {o['method']} {o['path']}  from {o['client']}")
    out.append("")
    out.append("## Endpoints sampled")
    for p in rep.endpoints[:60]:
        out.append(f"  {p}")
    out.append("")
    out.append("=" * 78)
    return "\n".join(out)


async def amain(args):
    rep = await run(args.target, args)
    Path(args.o).write_text(render(rep))
    Path(args.j).write_text(json.dumps(asdict(rep), indent=2, default=str))
    if args.sarif:
        Path(args.sarif).write_text(to_sarif(rep))
        print(f"[+] {args.sarif}")
    print()
    print(render(rep))
    print(f"\n[+] {args.o}")
    print(f"[+] {args.j}")
    return 1 if rep.hits else 0


def main():
    ap = argparse.ArgumentParser(prog="hunter",
        description="active vulnerability scanner on top of hunter_payloads")
    ap.add_argument("target")
    ap.add_argument("-o", default="hunter_report.txt")
    ap.add_argument("-j", default="hunter_report.json")
    ap.add_argument("-c", type=int, default=12)
    ap.add_argument("--depth", type=int, default=1)
    ap.add_argument("--cookies", default="")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--proxy", default="")
    ap.add_argument("--families", nargs="+", choices=list(FAMILIES))
    ap.add_argument("--no-oob", action="store_true")
    ap.add_argument("--oob-port", type=int, default=0)
    ap.add_argument("--no-content", action="store_true",
                    help="skip content discovery")
    ap.add_argument("--no-subs", action="store_true",
                    help="skip subdomain enumeration")
    ap.add_argument("--no-crt", action="store_true",
                    help="skip crt.sh, use DNS wordlist only")
    ap.add_argument("--sarif", default="", help="SARIF output path")
    ap.add_argument("--auth-login", default="")
    ap.add_argument("--auth-user", default="")
    ap.add_argument("--auth-pass", default="")
    ap.add_argument("--auth-csrf-meta", default=None)
    ap.add_argument("--auth-success-marker", default=None)
    ap.add_argument("--auth-verify", default=None)
    args = ap.parse_args()
    sys.exit(asyncio.run(amain(args)))


if __name__ == "__main__":
    main()
