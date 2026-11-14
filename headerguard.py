#!/usr/bin/env python3
"""headerguard - audit the HTTP security headers of your website. Zero dependencies.

    python headerguard.py https://example.com
    python headerguard.py --from-file saved-headers.txt

Each URL gets exactly one GET request. Only audit sites you own or administer.
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

__version__ = "1.0.0"

# rule id -> (default severity, title)
RULES: Dict[str, Tuple[str, str]] = {
    "HG001": ("error", "Strict-Transport-Security missing"),
    "HG002": ("warning", "HSTS max-age is too short (< 180 days)"),
    "HG003": ("info", "HSTS does not cover subdomains"),
    "HG004": ("error", "Content-Security-Policy missing"),
    "HG005": ("warning", "CSP allows unsafe script execution"),
    "HG006": ("warning", "CSP script sources are too broad"),
    "HG007": ("info", "CSP lacks object-src / base-uri / frame-ancestors"),
    "HG008": ("warning", "X-Content-Type-Options is not nosniff"),
    "HG009": ("warning", "No clickjacking protection"),
    "HG010": ("warning", "Referrer-Policy missing or leaky"),
    "HG011": ("info", "Permissions-Policy missing"),
    "HG012": ("info", "Cross-origin isolation headers missing"),
    "HG013": ("warning", "Server header discloses a version"),
    "HG014": ("warning", "Technology-disclosing header present"),
    "HG015": ("warning", "Cookie without Secure"),
    "HG016": ("warning", "Cookie without HttpOnly"),
    "HG017": ("info", "Cookie SameSite problem"),
    "HG018": ("error", "HTTP does not redirect to HTTPS"),
    "HG019": ("info", "Deprecated X-XSS-Protection enabled"),
    "HG020": ("error", "Permissive CORS policy"),
}

PENALTY = {"error": 15, "warning": 6, "info": 1}
SEV_RANK = {"info": 0, "warning": 1, "error": 2}
GRADES = (("A", 90), ("B", 80), ("C", 70), ("D", 60))
UNSAFE_REFERRER = {"unsafe-url", "no-referrer-when-downgrade", ""}
CSP_EXAMPLE = ("Content-Security-Policy: default-src 'self'; object-src 'none'; "
               "base-uri 'self'; frame-ancestors 'self'")


@dataclass
class Finding:
    rule: str
    severity: str
    header: str
    message: str
    fix: str = ""


@dataclass
class Report:
    url: str
    final_url: str
    status: Optional[int]
    score: int = 100
    grade: str = "A"
    findings: List[Finding] = field(default_factory=list)
    passed: List[str] = field(default_factory=list)


class Headers:
    """Case-insensitive header lookup that keeps Set-Cookie lines separate."""

    def __init__(self, items: Sequence[Tuple[str, str]]) -> None:
        self._h: Dict[str, str] = {}
        self.cookies: List[str] = []
        for k, v in items:
            lk, v = k.strip().lower(), v.strip()
            if lk == "set-cookie":
                self.cookies.append(v)
            elif lk in self._h:
                self._h[lk] = f"{self._h[lk]}, {v}"
            else:
                self._h[lk] = v

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self._h.get(name.lower(), default)

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._h


def parse_csp(value: str) -> Dict[str, List[str]]:
    directives: Dict[str, List[str]] = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if toks:
            directives.setdefault(toks[0].lower(), toks[1:])
    return directives


def grade_for(score: int) -> str:
    for letter, floor in GRADES:
        if score >= floor:
            return letter
    return "F"


def analyze(items: Sequence[Tuple[str, str]], url: str, final_url: Optional[str] = None,
            status: Optional[int] = None) -> Report:
    h = Headers(items)
    final_url = final_url or url
    https = final_url.lower().startswith("https://")
    findings: List[Finding] = []
    passed: List[str] = []

    def add(rule: str, header: str, message: str, fix: str = "", sev: Optional[str] = None) -> None:
        findings.append(Finding(rule, sev or RULES[rule][0], header, message, fix))

    def done(name: str, before: int) -> None:
        if len(findings) == before:
            passed.append(name)

    # HTTP -> HTTPS
    if url.lower().startswith("http://"):
        if https:
            passed.append("HTTP to HTTPS redirect")
        else:
            add("HG018", "(redirect)", "The plain HTTP URL did not redirect to HTTPS",
                "Redirect all HTTP traffic to HTTPS with a 301.")

    # HSTS
    if https:
        n = len(findings)
        hsts = h.get("strict-transport-security")
        if not hsts:
            add("HG001", "Strict-Transport-Security", "Header is missing",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains")
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15552000:
                add("HG002", "Strict-Transport-Security", f"max-age={age} is below 15552000 (180 days)",
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains")
            if "includesubdomains" not in hsts.lower():
                add("HG003", "Strict-Transport-Security", "includeSubDomains is not set",
                    "Append '; includeSubDomains' once every subdomain supports HTTPS.")
        done("Strict-Transport-Security", n)

    # CSP
    n = len(findings)
    csp = h.get("content-security-policy")
    report_only = h.get("content-security-policy-report-only")
    if not csp:
        msg = "Header is missing"
        if report_only:
            msg += " (Report-Only is set, but it blocks nothing)"
        add("HG004", "Content-Security-Policy", msg, CSP_EXAMPLE)
    else:
        d = parse_csp(csp)
        script = [s.lower() for s in d.get("script-src", d.get("default-src", []))]
        strict = any(s.startswith("'nonce-") or s.startswith("'sha") or s == "'strict-dynamic'"
                     for s in script)
        if not script:
            add("HG006", "Content-Security-Policy", "No script-src or default-src: scripts are unrestricted",
                "Add default-src 'self' as a baseline.")
        if "'unsafe-inline'" in script and not strict:
            add("HG005", "Content-Security-Policy", "script policy allows 'unsafe-inline'",
                "Use nonces or hashes instead of 'unsafe-inline'.")
        if "'unsafe-eval'" in script:
            add("HG005", "Content-Security-Policy", "script policy allows 'unsafe-eval'",
                "Remove 'unsafe-eval'; avoid eval() and new Function().")
        broad = [s for s in script if s in ("*", "http:", "https:", "data:")]
        if broad and "'strict-dynamic'" not in script:
            add("HG006", "Content-Security-Policy", f"Script sources too broad: {', '.join(broad)}",
                "List the exact origins you trust.")
        missing = [x for x in ("object-src", "base-uri", "frame-ancestors")
                   if x not in d and not (x == "object-src" and "default-src" in d)]
        if missing:
            add("HG007", "Content-Security-Policy", f"Missing directives: {', '.join(missing)}",
                "Add object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    done("Content-Security-Policy", n)

    # X-Content-Type-Options
    n = len(findings)
    xcto = h.get("x-content-type-options")
    if not xcto or xcto.lower() != "nosniff":
        add("HG008", "X-Content-Type-Options", "Header is missing or not 'nosniff'",
            "X-Content-Type-Options: nosniff")
    done("X-Content-Type-Options", n)

    # Clickjacking
    n = len(findings)
    has_fa = bool(csp) and "frame-ancestors" in parse_csp(csp or "")
    if not h.get("x-frame-options") and not has_fa:
        add("HG009", "X-Frame-Options", "Neither X-Frame-Options nor CSP frame-ancestors is set",
            "X-Frame-Options: DENY   (or CSP: frame-ancestors 'none')")
    done("Clickjacking protection", n)

    # Referrer-Policy
    n = len(findings)
    rp = h.get("referrer-policy")
    if rp is None:
        add("HG010", "Referrer-Policy", "Header is missing", "Referrer-Policy: strict-origin-when-cross-origin")
    elif rp.split(",")[-1].strip().lower() in UNSAFE_REFERRER:
        add("HG010", "Referrer-Policy", f"'{rp}' leaks full URLs",
            "Referrer-Policy: strict-origin-when-cross-origin")
    done("Referrer-Policy", n)

    # Permissions-Policy
    n = len(findings)
    if "permissions-policy" not in h and "feature-policy" not in h:
        add("HG011", "Permissions-Policy", "Header is missing",
            "Permissions-Policy: camera=(), microphone=(), geolocation=()")
    done("Permissions-Policy", n)

    # Cross-origin isolation
    n = len(findings)
    miss = [x for x in ("Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
                        "Cross-Origin-Embedder-Policy") if x not in h]
    if miss:
        add("HG012", ", ".join(miss), "Not set (optional hardening)",
            "Cross-Origin-Opener-Policy: same-origin")
    done("Cross-origin isolation", n)

    # Information disclosure
    n = len(findings)
    server = h.get("server")
    if server and re.search(r"\d+(\.\d+)+|/\s*\d", server):
        add("HG013", "Server", f"Reveals software version: {server}", "Hide or genericise the Server header.")
    for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        if name in h:
            add("HG014", name, f"Discloses technology: {h.get(name)}", f"Remove the {name} header.")
    done("No version disclosure", n)

    # Cookies
    for raw in h.cookies:
        parts = [p.strip() for p in raw.split(";")]
        cname = parts[0].split("=", 1)[0]
        attrs: Dict[str, str] = {}
        for p in parts[1:]:
            k, _, v = p.partition("=")
            attrs[k.strip().lower()] = v.strip()
        n = len(findings)
        if https and "secure" not in attrs:
            add("HG015", f"Set-Cookie: {cname}", "Missing the Secure attribute", "Add '; Secure'")
        if "httponly" not in attrs:
            add("HG016", f"Set-Cookie: {cname}", "Missing the HttpOnly attribute",
                "Add '; HttpOnly' unless scripts must read it.")
        ss = attrs.get("samesite")
        if ss is None:
            add("HG017", f"Set-Cookie: {cname}", "No SameSite attribute", "Add '; SameSite=Lax'")
        elif ss.lower() == "none" and "secure" not in attrs:
            add("HG017", f"Set-Cookie: {cname}", "SameSite=None requires Secure", "Add '; Secure'",
                sev="warning")
        done(f"Cookie {cname}", n)

    # CORS
    acao = h.get("access-control-allow-origin")
    if acao == "*":
        if (h.get("access-control-allow-credentials") or "").lower() == "true":
            add("HG020", "Access-Control-Allow-Origin", "Wildcard origin combined with credentials",
                "Echo a specific allow-listed origin instead of '*'.")
        else:
            add("HG020", "Access-Control-Allow-Origin", "Allows any origin to read responses",
                "Fine for public APIs; otherwise restrict to known origins.", sev="info")

    # Deprecated XSS filter header
    xss = h.get("x-xss-protection")
    if xss and xss.strip().startswith("1"):
        add("HG019", "X-XSS-Protection", f"'{xss}' enables a removed browser filter",
            "X-XSS-Protection: 0 (rely on CSP instead)")

    score = max(0, 100 - sum(PENALTY[f.severity] for f in findings))
    return Report(url, final_url, status, score, grade_for(score), findings, passed)


def parse_header_text(text: str) -> Tuple[List[Tuple[str, str]], Optional[int]]:
    """Parse `curl -sI` style output; with redirects, the last response wins."""
    blocks = [b for b in re.split(r"\r?\n\r?\n", text.strip()) if b.strip()]
    block = blocks[-1] if blocks else ""
    items: List[Tuple[str, str]] = []
    status: Optional[int] = None
    for line in block.splitlines():
        if line.upper().startswith("HTTP/"):
            parts = line.split()
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        elif ":" in line:
            k, v = line.split(":", 1)
            items.append((k, v))
    return items, status


def fetch(url: str, timeout: float, insecure: bool, extra: Dict[str, str],
          ua: str) -> Tuple[int, str, List[Tuple[str, str]]]:
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": ua, "Accept": "*/*"}
    headers.update(extra)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.geturl(), list(r.headers.items())
    except urllib.error.HTTPError as e:
        return e.code, e.geturl() or url, list(e.headers.items())


def normalize_url(raw: str) -> str:
    return raw if re.match(r"^https?://", raw, re.I) else "https://" + raw


def render_text(reports: List[Report]) -> str:
    lines: List[str] = []
    for r in reports:
        status = f" ({r.status})" if r.status else ""
        lines.append(f"{r.url}{status}   Grade {r.grade}  ({r.score}/100)")
        for f in sorted(r.findings, key=lambda x: (-SEV_RANK[x.severity], x.rule)):
            lines.append(f"  {f.severity.upper().ljust(7)} {f.rule}  {f.header}: {f.message}")
            if f.fix:
                lines.append(f"          fix: {f.fix}")
        if r.passed:
            lines.append("  PASSED  " + ", ".join(r.passed))
        lines.append("")
    return "\n".join(lines).rstrip()


def render_markdown(reports: List[Report]) -> str:
    out: List[str] = []
    for r in reports:
        out.append(f"## {r.url} - Grade {r.grade} ({r.score}/100)\n")
        if r.findings:
            out.append("| Severity | Rule | Header | Issue |")
            out.append("|---|---|---|---|")
            for f in sorted(r.findings, key=lambda x: (-SEV_RANK[x.severity], x.rule)):
                out.append(f"| {f.severity} | {f.rule} | `{f.header}` | {f.message} |")
        else:
            out.append("No issues found.")
        if r.passed:
            out.append("\nPassed: " + ", ".join(r.passed))
        out.append("")
    return "\n".join(out).rstrip()


def render_json(reports: List[Report]) -> str:
    return json.dumps({"version": __version__, "reports": [asdict(r) for r in reports]}, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="headerguard", description="Audit HTTP security headers.")
    p.add_argument("urls", nargs="*", help="URLs to audit (https:// is assumed when omitted).")
    p.add_argument("--from-file", metavar="FILE", help="Audit saved headers (e.g. from `curl -sIL`).")
    p.add_argument("--url", help="URL the saved headers came from (sets the scheme for --from-file).")
    p.add_argument("-f", "--format", choices=("text", "json", "markdown"), default="text")
    p.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                   help="Extra request header, e.g. for auth. Repeatable.")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--user-agent", default=f"headerguard/{__version__}")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification (testing only).")
    p.add_argument("--fail-on", choices=("info", "warning", "error", "never"), default="error",
                   help="Lowest severity that makes the exit code 1 (default: error).")
    p.add_argument("--min-grade", choices=("A", "B", "C", "D"),
                   help="Exit 1 when any grade is worse than this.")
    p.add_argument("--list-rules", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"headerguard {__version__}")
    a = p.parse_args(argv)

    if a.list_rules:
        for rid, (sev, title) in RULES.items():
            print(f"{rid}  {sev.ljust(7)}  {title}")
        return 0
    if not a.urls and not a.from_file:
        p.error("give at least one URL or --from-file")

    extra: Dict[str, str] = {}
    for raw in a.header:
        if ":" not in raw:
            p.error(f"bad --header value: {raw!r}")
        k, v = raw.split(":", 1)
        extra[k.strip()] = v.strip()

    reports: List[Report] = []
    failed = False
    if a.from_file:
        try:
            with open(a.from_file, encoding="utf-8", errors="replace") as fh:
                items, status = parse_header_text(fh.read())
        except OSError as e:
            print(f"headerguard: {e}", file=sys.stderr)
            return 2
        url = normalize_url(a.url or "example.invalid")
        reports.append(analyze(items, url, url, status))
    for raw in a.urls:
        url = normalize_url(raw)
        try:
            status, final, items = fetch(url, a.timeout, a.insecure, extra, a.user_agent)
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"headerguard: {url}: {getattr(e, 'reason', e)}", file=sys.stderr)
            failed = True
            continue
        reports.append(analyze(items, url, final, status))

    if reports:
        renderer = {"text": render_text, "json": render_json, "markdown": render_markdown}[a.format]
        print(renderer(reports))
    if failed and not reports:
        return 2

    code = 0
    if a.fail_on != "never":
        worst = max((SEV_RANK[f.severity] for r in reports for f in r.findings), default=-1)
        if worst >= SEV_RANK[a.fail_on]:
            code = 1
    if a.min_grade and any(r.grade > a.min_grade for r in reports):
        code = 1
    return 2 if failed else code


if __name__ == "__main__":
    sys.exit(main())
