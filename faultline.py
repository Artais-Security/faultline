#!/usr/bin/env python3
"""faultline - A probe for OWASP Top 10:2025 A10 (Mishandling of Exceptional Conditions).

Sends a battery of malformed / unexpected inputs at a target endpoint and analyzes
the responses for signs that the application mishandles exceptional conditions:

  * verbose error / stack-trace disclosure (framework debug pages, tracebacks)
  * sensitive information leakage in errors (SQL errors, file paths, internal hosts)
  * unhandled server-side exceptions (5xx where graceful handling is expected)
  * inconsistent status-code / error-body handling relative to a clean baseline

Single-file, stdlib-only, Python 3.8+. No third-party dependencies.

Usage:
    faultline https://target/api/item?id=1
    faultline https://target/api/item -X POST -d '{"id":1,"q":"x"}' -H 'Authorization: Bearer ...'
    faultline https://target/api/item?id=1 --json -o findings.json --fail-on medium

Exit codes:
    0  completed, no findings at/above the --fail-on threshold
    1  findings at/above the --fail-on threshold
    2  usage error, or the target could not be reached at all
"""

import argparse
import http.client
import json
import re
import socket
import ssl
import sys
import time
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

__version__ = "0.1.0"

# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #

_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
}


class Out:
    def __init__(self, color):
        self.color = color

    def c(self, text, *styles):
        if not self.color:
            return text
        return "".join(_ANSI[s] for s in styles) + text + _ANSI["reset"]


# Severity ordering, low index = more severe.
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_COLOR = {
    "critical": "magenta", "high": "red", "medium": "yellow",
    "low": "cyan", "info": "dim",
}

# --------------------------------------------------------------------------- #
# Detection signatures
# --------------------------------------------------------------------------- #
# Each signature: (id, severity, human title, compiled regex).
# Ordered roughly most-specific-first; a single finding is raised per (probe, sig).

def _rx(p):
    return re.compile(p, re.IGNORECASE | re.MULTILINE)


SIGNATURES = [
    # -- Interactive debuggers (worst case: often RCE-adjacent) ------------- #
    ("werkzeug-debugger", "critical", "Werkzeug interactive debugger exposed",
     _rx(r"Werkzeug Debugger|The debugger caught an exception|__debugger__")),
    ("rails-web-console", "critical", "Rails web-console / better_errors exposed",
     _rx(r"better_errors|web-console|<title>\s*Action Controller: Exception caught")),

    # -- Framework debug / stack-trace pages -------------------------------- #
    ("django-debug", "high", "Django debug page (DEBUG=True)",
     _rx(r"You're seeing this error because you have\s*DEBUG\s*=\s*True|Django Version:|Exception Value:")),
    ("aspnet-yellow", "high", "ASP.NET detailed server error",
     _rx(r"Server Error in '.*?' Application|Microsoft \.NET Framework Version:|\[SqlException")),
    ("java-stacktrace", "high", "Java stack trace disclosed",
     _rx(r"(?:^|\s)at [\w.$]+\([\w.]+\.java:\d+\)|Caused by: [\w.$]+Exception|javax\.servlet|org\.springframework\.")),
    ("php-fatal", "high", "PHP fatal error / uncaught exception",
     _rx(r"<b>Fatal error</b>|Uncaught \w+Error:|PHP Fatal error|Stack trace:\s*#0")),
    ("python-traceback", "high", "Python traceback disclosed",
     _rx(r"Traceback \(most recent call last\):|File \".*?\", line \d+, in ")),
    ("node-stacktrace", "high", "Node.js stack trace disclosed",
     _rx(r"at (?:Object\.<anonymous>|Module\._compile|Function\.Module)|\bnode_modules[\\/]|/app/[\w./-]+:\d+:\d+")),
    ("ruby-stacktrace", "high", "Ruby stack trace disclosed",
     _rx(r"\.rb:\d+:in `|ActionView::|ActiveRecord::|NoMethodError")),

    # -- SQL / datastore errors -------------------------------------------- #
    ("sql-error", "high", "SQL error message leaked",
     _rx(r"SQLSTATE\[|SQL syntax.*?MySQL|Unclosed quotation mark after|"
         r"quoted string not properly terminated|ORA-\d{5}|"
         r"PostgreSQL.*?ERROR|SQLite3::|psql: error|Npgsql\.")),

    # -- PHP notices / warnings (lower signal, still leakage) --------------- #
    ("php-warning", "medium", "PHP warning/notice disclosed",
     _rx(r"<b>Warning</b>:|<b>Notice</b>:| on line <b>\d+</b>")),

    # -- Sensitive path / host disclosure ----------------------------------- #
    ("fs-path", "medium", "Filesystem path disclosed",
     _rx(r"(?:/var/www/|/home/\w+/|/usr/local/|/opt/app/|[A-Za-z]:\\\\?(?:inetpub|Users|www))[\w./\\-]+")),
    ("internal-host", "medium", "Internal host / private IP disclosed",
     _rx(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
    ("dsn-secret", "medium", "Connection string / DSN fragment leaked",
     _rx(r"(?:DATABASE_URL|connectionString|Data Source=|Server=.*?;Uid=|mongodb(?:\+srv)?://)")),

    # -- Generic exception words (weak, only counts if server also erred) ---- #
    ("generic-exception", "low", "Generic exception keyword in response body",
     _rx(r"\bException\b|\bStack ?[Tt]race\b|Internal Server Error|Unhandled exception")),
]

# --------------------------------------------------------------------------- #
# Probe (payload) catalog
# --------------------------------------------------------------------------- #
# Value-level payloads injected into a chosen parameter / JSON field.

def value_probes(max_len):
    long_val = "A" * max_len
    return [
        ("oversized", long_val, "very long value (length overflow)"),
        ("empty", "", "empty value where one is expected"),
        ("null-byte", "x%00y", "embedded null byte"),
        ("negative-int", "-1", "negative integer"),
        ("huge-int", "9" * 40, "oversized integer"),
        ("float-edge", "NaN", "non-numeric float token"),
        ("special-chars", "'\"\\`;|<>{}$()", "shell/meta special characters"),
        ("format-string", "%s%n%x{0}${env}", "format-string / template tokens"),
        ("bad-unicode", "%ed%a0%80", "invalid UTF-8 (lone surrogate)"),
        ("crlf", "a%0d%0anewheader:1", "CRLF injection attempt"),
    ]


# JSON-structural payloads: swap a scalar field for a wrong type.
def json_structural_probes(depth=40):
    nested = 0
    for _ in range(depth):
        nested = [nested]
    return [
        ("type-array", [], "scalar field replaced with array"),
        ("type-object", {"unexpected": True}, "scalar field replaced with object"),
        ("type-null", None, "scalar field replaced with null"),
        ("type-bool", True, "scalar field replaced with boolean"),
        ("deep-nest", nested, "deeply nested array (parser stress)"),
    ]


# Request-level (body / header) probes, independent of any parameter.
def request_probes(has_body, content_type, max_len):
    probes = []
    probes.append(("malformed-json-body", {
        "body": '{"a": ', "content_type": "application/json",
    }, "truncated JSON body with JSON content-type"))
    probes.append(("json-ct-nonjson", {
        "body": "this is not json at all", "content_type": "application/json",
    }, "non-JSON body served as application/json"))
    probes.append(("wrong-content-type", {
        "body": '{"a":1}', "content_type": "application/xml",
    }, "JSON body mislabeled as application/xml"))
    probes.append(("oversized-body", {
        "body": "x" * max_len, "content_type": content_type or "text/plain",
    }, "oversized request body"))
    probes.append(("bad-charset", {
        "body": '{"a":1}', "content_type": "application/json; charset=invalid-999",
    }, "invalid charset in content-type"))
    return probes


# --------------------------------------------------------------------------- #
# HTTP transport
# --------------------------------------------------------------------------- #

class Response:
    __slots__ = ("status", "reason", "headers", "body", "elapsed", "error")

    def __init__(self, status=0, reason="", headers=None, body="", elapsed=0.0, error=None):
        self.status = status
        self.reason = reason
        self.headers = headers or {}
        self.body = body
        self.elapsed = elapsed
        self.error = error


def build_context(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send(method, url, headers, body, timeout, insecure, body_cap):
    """Send one request via http.client. Returns a Response (never raises)."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return Response(error="could not parse host from URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    conn = None
    start = time.monotonic()
    try:
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=build_context(insecure))
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        send_headers = dict(headers)
        data = body.encode("utf-8", "surrogateescape") if isinstance(body, str) else body
        if data is not None:
            send_headers.setdefault("Content-Length", str(len(data)))

        conn.request(method, path, body=data, headers=send_headers)
        resp = conn.getresponse()
        raw = resp.read(body_cap)
        elapsed = time.monotonic() - start
        text = raw.decode("utf-8", "replace")
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return Response(resp.status, resp.reason, hdrs, text, elapsed)
    except (socket.timeout, TimeoutError):
        return Response(elapsed=time.monotonic() - start, error="timeout")
    except (http.client.HTTPException, ConnectionError, OSError, ssl.SSLError) as e:
        return Response(elapsed=time.monotonic() - start,
                        error="{}: {}".format(type(e).__name__, e))
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

class Finding:
    def __init__(self, sev, sig_id, title, probe_id, probe_desc, where,
                 status, evidence, request):
        self.sev = sev
        self.sig_id = sig_id
        self.title = title
        self.probe_id = probe_id
        self.probe_desc = probe_desc
        self.where = where
        self.status = status
        self.evidence = evidence
        self.request = request

    def to_dict(self):
        return {
            "severity": self.sev,
            "signature": self.sig_id,
            "title": self.title,
            "probe": self.probe_id,
            "probe_description": self.probe_desc,
            "injected_at": self.where,
            "response_status": self.status,
            "evidence": self.evidence,
            "request": self.request,
        }


def scan_body(text):
    """Return list of (sig_id, sev, title, snippet) for every signature that hits."""
    hits = []
    for sig_id, sev, title, rx in SIGNATURES:
        m = rx.search(text)
        if m:
            snippet = _snippet(text, m.start(), m.end())
            hits.append((sig_id, sev, title, snippet))
    return hits


def _snippet(text, start, end, radius=60):
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    frag = text[lo:hi].replace("\n", "\\n").replace("\r", "")
    frag = re.sub(r"\s{2,}", " ", frag).strip()
    return ("..." if lo > 0 else "") + frag + ("..." if hi < len(text) else "")


def classify(baseline, resp, hits):
    """Decide whether this response is interesting relative to baseline.

    Returns a list of (severity, sig_id, title, evidence) tuples. Status-code
    anomalies (unhandled 5xx) are folded in as synthetic signatures.
    """
    results = []
    server_errored = 500 <= resp.status < 600

    for sig_id, sev, title, snippet in hits:
        # "generic-exception" alone is noise unless the server also errored or
        # the baseline did not contain it (i.e. the probe *introduced* it).
        if sig_id == "generic-exception":
            if not server_errored and title_in_baseline(baseline, sig_id):
                continue
        results.append((sev, sig_id, title, snippet))

    # Unhandled server error with no richer signature already captured.
    if server_errored and not any(r[1] != "generic-exception" for r in results):
        base_status = baseline.status if baseline else 0
        if not (baseline and 500 <= base_status < 600):
            results.append((
                "medium", "unhandled-5xx",
                "Unhandled server error ({})".format(resp.status),
                "server returned {} {} to malformed input".format(resp.status, resp.reason),
            ))
    return results


_BASELINE_SIG_CACHE = {}


def title_in_baseline(baseline, sig_id):
    if not baseline or not baseline.body:
        return False
    key = id(baseline)
    cache = _BASELINE_SIG_CACHE.setdefault(key, {})
    if sig_id not in cache:
        cache[sig_id] = any(h[0] == sig_id for h in scan_body(baseline.body))
    return cache[sig_id]


# --------------------------------------------------------------------------- #
# Target model / probe planning
# --------------------------------------------------------------------------- #

def parse_headers(pairs):
    headers = {}
    for item in pairs or []:
        if ":" not in item:
            raise ValueError("bad header (expected 'Name: value'): {}".format(item))
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def with_query(url, params):
    parsed = urlparse(url)
    new_q = urlencode(params, doseq=True, safe="%")
    return urlunparse(parsed._replace(query=new_q))


def plan(url, method, data, headers, max_len):
    """Yield (probe_id, probe_desc, where, method, url, body, headers) tuples."""
    parsed = urlparse(url)
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    ctype = headers.get("Content-Type") or headers.get("content-type")

    json_body = None
    if data:
        try:
            loaded = json.loads(data)
            if isinstance(loaded, dict):
                json_body = loaded
        except (ValueError, TypeError):
            json_body = None

    # 1. Value-level probes into each query parameter.
    for i, (k, _v) in enumerate(query_params):
        for pid, payload, desc in value_probes(max_len):
            mutated = list(query_params)
            mutated[i] = (k, payload)
            yield (pid, desc, "query:{}".format(k), method,
                   with_query(url, mutated), data, headers)

    # 2. Value + structural probes into each top-level JSON field.
    if json_body is not None:
        for field in list(json_body.keys()):
            for pid, payload, desc in value_probes(max_len):
                mutated = dict(json_body)
                mutated[field] = payload
                yield (pid, desc, "json:{}".format(field), method, url,
                       json.dumps(mutated), _ensure_json_ct(headers))
            for pid, payload, desc in json_structural_probes():
                mutated = dict(json_body)
                mutated[field] = payload
                yield (pid, desc, "json:{}".format(field), method, url,
                       json.dumps(mutated), _ensure_json_ct(headers))

    # 3. Request-level probes (body / header level).
    has_body = data is not None
    for pid, spec, desc in request_probes(has_body, ctype, max_len):
        h = dict(headers)
        h["Content-Type"] = spec["content_type"]
        yield (pid, desc, "request-body", method, url, spec["body"], h)


def _ensure_json_ct(headers):
    h = dict(headers)
    if not any(k.lower() == "content-type" for k in h):
        h["Content-Type"] = "application/json"
    return h


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

def run(args, out):
    headers = parse_headers(args.header)
    headers.setdefault("User-Agent", args.user_agent)
    headers.setdefault("Accept", "*/*")

    method = args.method.upper()
    if args.data and method == "GET":
        method = "POST"  # a body implies a body-bearing method

    # Baseline.
    if not args.json_out:
        print(out.c("faultline {}".format(__version__), "bold"),
              "->", out.c(args.url, "cyan"))
        print(out.c("  sending baseline request...", "dim"))
    baseline = send(method, args.url, headers, args.data,
                    args.timeout, args.insecure, args.body_cap)
    if baseline.error and baseline.status == 0:
        msg = "target unreachable: {}".format(baseline.error)
        if args.json_out:
            print(json.dumps({"error": msg, "target": args.url}))
        else:
            print(out.c("  " + msg, "red"))
        return 2, []

    if not args.json_out:
        print("  baseline: {} {}  ({} bytes, {:.0f} ms)".format(
            out.c(str(baseline.status), "green" if baseline.status < 400 else "yellow"),
            baseline.reason, len(baseline.body), baseline.elapsed * 1000))

    findings = []
    sent = 0
    probes = list(plan(args.url, method, args.data, headers, args.max_len))
    if args.baseline_only:
        probes = []

    for (pid, desc, where, m, url, body, hdrs) in probes:
        if args.max_requests and sent >= args.max_requests:
            if not args.json_out:
                print(out.c("  request cap reached ({}); stopping".format(
                    args.max_requests), "dim"))
            break
        resp = send(m, url, hdrs, body, args.timeout, args.insecure, args.body_cap)
        sent += 1
        if args.delay:
            time.sleep(args.delay)
        if resp.error and resp.status == 0:
            if args.verbose and not args.json_out:
                print(out.c("    [{}] {} -> {}".format(pid, where, resp.error), "dim"))
            continue

        hits = scan_body(resp.body)
        results = classify(baseline, resp, hits)
        for sev, sig_id, title, evidence in results:
            req_repr = "{} {}".format(m, url)
            if body:
                req_repr += "  body={}".format(_trunc(body, 80))
            f = Finding(sev, sig_id, title, pid, desc, where,
                        resp.status, evidence, req_repr)
            findings.append(f)
            if args.verbose and not args.json_out:
                _print_finding(f, out)

    findings.sort(key=lambda f: (SEV_RANK.get(f.sev, 99), f.where))
    return report(args, out, baseline, findings, sent)


def _trunc(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n] + "..."


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def _print_finding(f, out):
    tag = out.c("[{}]".format(f.sev.upper()), SEV_COLOR.get(f.sev, "reset"), "bold")
    print("  {} {}".format(tag, out.c(f.title, "bold")))
    print("      probe   : {} ({})".format(f.probe_id, f.probe_desc))
    print("      at      : {}   status: {}".format(f.where, f.status))
    print("      evidence: {}".format(out.c(f.evidence, "dim")))
    print("      request : {}".format(out.c(f.request, "dim")))


def report(args, out, baseline, findings, sent):
    threshold = SEV_RANK[args.fail_on] if args.fail_on != "none" else -1
    triggering = [f for f in findings if SEV_RANK.get(f.sev, 99) <= threshold]

    if args.json_out:
        payload = {
            "tool": "faultline",
            "version": __version__,
            "target": args.url,
            "baseline_status": baseline.status,
            "requests_sent": sent,
            "fail_on": args.fail_on,
            "summary": _summary(findings),
            "findings": [f.to_dict() for f in findings],
        }
        text = json.dumps(payload, indent=2)
        if args.output:
            with open(args.output, "w") as fh:
                fh.write(text + "\n")
        else:
            print(text)
    else:
        print()
        if not findings:
            print(out.c("  no exceptional-condition issues detected", "green"),
                  out.c("({} probes sent)".format(sent), "dim"))
        else:
            if not args.verbose:
                for f in findings:
                    _print_finding(f, out)
                    print()
            counts = _summary(findings)
            parts = ["{} {}".format(counts[s], s) for s in SEVERITIES if counts.get(s)]
            print(out.c("  summary: ", "bold") + ", ".join(parts) +
                  out.c("  ({} probes sent)".format(sent), "dim"))
        if args.output:
            with open(args.output, "w") as fh:
                json.dump({"target": args.url,
                           "findings": [f.to_dict() for f in findings]}, fh, indent=2)
            print(out.c("  written: {}".format(args.output), "dim"))

    return (1 if triggering else 0), findings


def _summary(findings):
    counts = {}
    for f in findings:
        counts[f.sev] = counts.get(f.sev, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        prog="faultline",
        description="Probe a web endpoint for mishandling of exceptional "
                    "conditions (OWASP Top 10:2025 A10).",
        epilog="Only test systems you are authorized to assess.",
    )
    p.add_argument("url", help="target URL (include any query parameters to fuzz)")
    p.add_argument("-X", "--method", default="GET", help="HTTP method (default: GET)")
    p.add_argument("-d", "--data", default=None,
                   help="request body; if valid JSON, top-level fields are fuzzed")
    p.add_argument("-H", "--header", action="append", default=[],
                   metavar="'Name: value'", help="extra header (repeatable)")
    p.add_argument("--user-agent", default="faultline/{}".format(__version__),
                   help="User-Agent header value")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="per-request timeout in seconds (default: 15)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="delay between requests in seconds (be kind to live targets)")
    p.add_argument("--max-len", type=int, default=8192,
                   help="length of oversized payloads (default: 8192)")
    p.add_argument("--max-requests", type=int, default=0,
                   help="cap total probe requests (0 = no cap)")
    p.add_argument("--body-cap", type=int, default=524288,
                   help="max response bytes read/scanned (default: 512 KiB)")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="low",
                   help="min severity that sets exit code 1 (default: low)")
    p.add_argument("--baseline-only", action="store_true",
                   help="send only the baseline request, then report")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="skip TLS certificate verification")
    p.add_argument("--json", dest="json_out", action="store_true",
                   help="emit findings as JSON")
    p.add_argument("-o", "--output", default=None, help="write findings to a file")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="stream findings as they are discovered")
    p.add_argument("--version", action="version",
                   version="faultline {}".format(__version__))
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    use_color = (not args.no_color) and (not args.json_out) and sys.stdout.isatty()
    out = Out(use_color)
    try:
        code, _ = run(args, out)
        return code
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 2
    except ValueError as e:
        print("error: {}".format(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
