"""Form-based authentication with CSRF."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlencode
from bs4 import BeautifulSoup

@dataclass
class AuthConfig:
    login_url: str
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: Optional[str] = None
    csrf_meta: Optional[str] = None
    extra: Dict[str, str] = field(default_factory=dict)
    success_marker: Optional[str] = None
    verify_url: Optional[str] = None

async def login(client, cfg):
    notes = []
    s, h, b, _ = await client.req("GET", cfg.login_url)
    if s != 200:
        return False, [f"login_page_status={s}"]
    soup = BeautifulSoup(b.decode("utf-8", errors="ignore"), "html.parser")
    form = None
    for f in soup.find_all("form"):
        if any((i.get("type") or "").lower() == "password" for i in f.find_all("input")):
            form = f
            break
    action = urljoin(cfg.login_url, (form.get("action") if form else "") or cfg.login_url)
    method = ((form.get("method") if form else "POST") or "POST").upper()
    fields = {}
    if form:
        for i in form.find_all(["input", "textarea"]):
            n = i.get("name")
            if not n:
                continue
            if (i.get("type") or "").lower() == "submit":
                continue
            fields[n] = i.get("value", "")
    uf, pf = cfg.username_field, cfg.password_field
    for n in list(fields.keys()):
        nl = n.lower()
        if "user" in nl or "email" in nl or "login" in nl:
            uf = n
        if "pass" in nl:
            pf = n
    fields[uf] = cfg.username
    fields[pf] = cfg.password
    cf = cfg.csrf_field
    cv = None
    for n in list(fields.keys()):
        nl = n.lower()
        if "csrf" in nl or "token" in nl:
            cf = n
            cv = fields[n]
            notes.append(f"csrf_field:{n}")
            break
    if not cv and cfg.csrf_meta:
        m = soup.find("meta", attrs={"name": cfg.csrf_meta})
        if m and m.get("content"):
            cf = cf or cfg.csrf_meta
            cv = m["content"]
            notes.append(f"csrf_meta:{cfg.csrf_meta}")
    if cf and cv:
        fields[cf] = cv
    for k, v in cfg.extra.items():
        fields[k] = v
    s2, h2, b2, _ = await client.req(method, action,
        data=urlencode(fields).encode(),
        extra_headers={"Content-Type": "application/x-www-form-urlencoded",
                       "Referer": cfg.login_url},
        allow_redirects=True)
    notes.append(f"submit_status={s2}")
    if cfg.success_marker:
        ok = cfg.success_marker in b2.decode("utf-8", errors="ignore")
    else:
        ok = s2 in (200, 302, 303) and b2[:500] != b[:500]
    if ok and cfg.verify_url:
        sv, _, _, _ = await client.req("GET", cfg.verify_url)
        notes.append(f"verify_status={sv}")
        if sv != 200:
            ok = False
    jar = [c.key for c in client.session.cookie_jar]
    notes.append("cookies:" + ",".join(jar))
    if not jar:
        ok = False
    return ok, notes
