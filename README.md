# hunter — active vulnerability scanner

Payload-driven scanner. 211 payloads, 16 families. Confirms with evidence, no false positives.

## Install

    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt

## Run

    python hunter.py https://target.example/ -c 10 --depth 2

## Output

- hunter_report.txt — hits sorted by severity, with request/response proof
- hunter_report.json — structured
- hunter_report.sarif — SARIF 2.1.0 for CI

## Flags

-c N | --depth N | --cookies 'session=...' | --header 'X: y' | --proxy URL
--families xss sqli lfi | --no-oob | --no-content | --no-subs | --no-crt
--sarif out.sarif | --auth-login URL --auth-user U --auth-pass P

## Legal

Authorized targets only. sqli_stacked contains DROP TABLE — disable with --families on non-owned systems.

MIT.
