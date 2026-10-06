"""Deduplicate hits: same (url, param, vuln_class) → one finding."""
from __future__ import annotations
from typing import List, Dict, Any

XSS_CLASSES = {"xss", "xss_js", "xss_js_context", "xss_waf_evasion", "json_xss"}
SQLI_CLASSES = {"sqli", "sqli_error", "sqli_union", "sqli_time",
                "sqli_boolean", "sqli_stacked", "json_sqli"}
CMDI_CLASSES = {"cmdi", "cmdi_time", "blind_cmdi"}
SSRF_CLASSES = {"ssrf", "blind_ssrf"}
LFI_CLASSES = {"lfi"}
SSTI_CLASSES = {"ssti"}
REDIRECT_CLASSES = {"redirect", "open_redirect"}
CRLF_CLASSES = {"crlf", "header_inject"}
XXE_CLASSES = {"xxe", "xxe_oob"}
NOSQL_CLASSES = {"nosql", "nosql_auth_bypass"}
GRAPHQL_CLASSES = {"graphql", "graphql_introspection"}


def vuln_class(family: str) -> str:
    if family in XSS_CLASSES: return "xss"
    if family in SQLI_CLASSES: return "sqli"
    if family in CMDI_CLASSES: return "cmdi"
    if family in SSRF_CLASSES: return "ssrf"
    if family in LFI_CLASSES: return "lfi"
    if family in SSTI_CLASSES: return "ssti"
    if family in REDIRECT_CLASSES: return "open_redirect"
    if family in CRLF_CLASSES: return "crlf"
    if family in XXE_CLASSES: return "xxe"
    if family in NOSQL_CLASSES: return "nosql"
    if family in GRAPHQL_CLASSES: return "graphql_introspection"
    return family


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def dedup(hits: List[Any]) -> List[Any]:
    """Return one hit per (url, param, vuln_class), merging payloads."""
    buckets: Dict[str, List[Any]] = {}
    for h in hits:
        vc = vuln_class(h.family)
        key = f"{h.method}|{h.url}|{h.param}|{vc}"
        buckets.setdefault(key, []).append(h)

    merged: List[Any] = []
    for key, group in buckets.items():
        group.sort(key=lambda x: SEVERITY_RANK.get(x.severity, 0), reverse=True)
        primary = group[0]
        if len(group) > 1:
            payloads = []
            for g in group:
                p = g.payload
                if p not in payloads:
                    payloads.append(p)
            evidence_block = "\n        ".join(
                f"[{g.family}] {g.evidence[:120]}" for g in group
            )
            primary.evidence = (
                f"confirmed by {len(group)} families "
                f"({', '.join(sorted({g.family for g in group}))}):\n        "
                f"{evidence_block}"
            )
            primary.payload = " | ".join(payloads[:5])
        merged.append(primary)

    merged.sort(key=lambda x: SEVERITY_RANK.get(x.severity, 0), reverse=True)
    return merged
