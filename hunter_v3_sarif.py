"""SARIF 2.1.0 output."""
import json
LEVEL_MAP = {"critical": "error", "high": "error", "medium": "warning",
             "low": "note", "info": "note"}
RULE_HELP = {
    "xss": "Cross-site scripting.",
    "sqli": "SQL injection.",
    "lfi": "Local file inclusion.",
    "cmdi": "Command injection.",
    "ssti": "Server-side template injection.",
    "ssrf": "Server-side request forgery.",
    "open_redirect": "Open redirect.",
    "crlf": "CRLF injection.",
    "xxe": "XML external entity.",
    "nosql": "NoSQL injection.",
    "graphql_introspection": "GraphQL introspection enabled.",
}
def to_sarif(rep):
    rules = {}
    results = []
    for h in rep.hits:
        rid = h.family
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid.replace("_", " ").title(),
                "shortDescription": {"text": rid},
                "fullDescription": {"text": RULE_HELP.get(rid, rid)},
                "defaultConfiguration": {"level": LEVEL_MAP.get(h.severity, "warning")},
            }
        results.append({
            "ruleId": rid,
            "level": LEVEL_MAP.get(h.severity, "warning"),
            "message": {"text": f"{rid} on {h.url} [{h.param}] — {h.evidence[:200]}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": h.url},
                "region": {"startLine": 1}}}],
            "properties": {"severity": h.severity, "confidence": h.confidence,
                           "payload": h.payload[:500], "method": h.method,
                           "parameter": h.param},
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "hunter", "version": "3.0",
                                "rules": list(rules.values())}},
            "results": results,
            "invocations": [{"executionSuccessful": True,
                             "startTimeUtc": rep.started,
                             "endTimeUtc": rep.finished}],
        }],
    }
    return json.dumps(sarif, indent=2, default=str)
