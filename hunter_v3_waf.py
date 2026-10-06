"""WAF detection."""
import re
WAF_PATTERNS = [
    ("cloudflare", [r"cf-ray", r"cloudflare", r"__cf_bm"]),
    ("akamai", [r"akamai", r"x-akamai"]),
    ("fastly", [r"fastly", r"x-served-by", r"x-fastly"]),
    ("cloudfront", [r"cloudfront", r"x-amz-cf"]),
    ("imperva", [r"imperva", r"incapsula", r"x-iinfo"]),
    ("sucuri", [r"sucuri", r"x-sucuri"]),
    ("modsecurity", [r"mod_security", r"modsecurity", r"not acceptable"]),
    ("f5_bigip", [r"big-ip", r"bigip", r"x-wa-info"]),
    ("barracuda", [r"barracuda", r"barra_counter_session"]),
    ("fortiweb", [r"fortiweb", r"fortigate"]),
    ("wallarm", [r"wallarm", r"nginx-wallarm"]),
    ("aws_waf", [r"awselb", r"x-amzn-requestid"]),
]
WAF_BODY_MARKERS = [
    r"attention required", r"request blocked", r"access denied.*security",
    r"cloudflare ray id", r"security check",
]
def detect_waf(status, headers, body):
    blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    body_text = body[:8000].decode("utf-8", errors="ignore").lower()
    hits = {}
    for name, patterns in WAF_PATTERNS:
        for p in patterns:
            if re.search(p, blob):
                hits[name] = hits.get(name, 0) + 1
    body_signal = any(re.search(m, body_text) for m in WAF_BODY_MARKERS)
    if not hits and not body_signal:
        return "", 0.0
    if hits:
        name, count = max(hits.items(), key=lambda kv: kv[1])
        conf = min(0.95, 0.5 + count * 0.15)
        if body_signal:
            conf = min(0.99, conf + 0.1)
        return name, conf
    return "unknown-waf", 0.5
