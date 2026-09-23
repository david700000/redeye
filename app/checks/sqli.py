import uuid
import re
import httpx

from ..config import REQUEST_TIMEOUT_SECONDS
from ..crawler import Endpoint

# (true_condition, false_condition) pairs. Tried in order per parameter;
# first pair that produces a clear true/false divergence is reported.
PROBE_PAIRS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
    # Numeric-context probes (e.g. WHERE id=1 AND 1=1)
    ("1 AND 1=1--", "1 AND 1=2--"),
    ("1 AND 1=1#", "1 AND 1=2#"),
]

# Error-based detection payloads
ERROR_PAYLOADS = ["'", "\"", "1'", "1\"", "1 OR 1=1--", "1'--"]

# Common SQL error signatures from MySQL, SQLite, PostgreSQL, MSSQL, Oracle, JDBC, DB2
SQL_ERROR_PATTERNS = re.compile(
    r"(you have an error in your sql syntax"
    r"|warning: mysql"
    r"|mysql_fetch"
    r"|pg_query\(\)"
    r"|supplied argument is not a valid mysql"
    r"|sqlite_exception"
    r"|sqlite error"
    r"|unclosed quotation mark"
    r"|quoted string not properly terminated"
    r"|ora-\d{5}"
    r"|microsoft jet database"
    r"|microsoft ole db"
    r"|odbc sql server driver"
    r"|odbc driver"
    r"|syntax error.*sql"
    r"|sql syntax.*error"
    r"|division by zero"
    r"|invalid query"
    r"|unterminated string literal"
    r"|psql.*error"
    r"|db2 sql error"
    r"|com\.mysql\.jdbc"
    r"|java\.sql\.sqlexception)",
    re.IGNORECASE,
)


async def check_sqli(
    endpoints: list[Endpoint],
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> list[dict]:
    """
    Three-pass SQLi heuristic:

    1. Error-based: inject a syntax-breaking payload via GET params, cookie values,
       and POST body fields, then check response for recognisable DB error strings.
       Fast and reliable on apps that expose raw errors (testphp.vulnweb.com, DVWA easy,
       PortSwigger labs with TrackingId cookie).

    2. Boolean-based blind (GET): send true/false payloads via URL params and compare
       response lengths.  Works on apps that suppress errors but show different content
       for matching vs non-matching WHERE clauses.

    3. Boolean-based blind (cookies): same approach, but injected via cookie values.
       Covers PortSwigger's TrackingId-style labs.
    """
    cookies = cookies or {}
    headers = headers or {}
    findings = []
    reported: set[tuple[str, str, str]] = set()  # (path, injection_type, param)

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS,
        follow_redirects=True,
        cookies=cookies,
        headers=headers,
    ) as client:
        for ep in endpoints:
            # ── GET query-string params ───────────────────────────────────
            if ep.method == "GET" and ep.params:
                baseline_len = await _get_baseline(client, ep.url)

                for param in ep.params:
                    key = (ep.path, "get", param)
                    if key in reported:
                        continue

                    # Pass 1: error-based via GET param
                    for err_payload in ERROR_PAYLOADS:
                        err_url = _build_test_url(ep.url, param, err_payload)
                        try:
                            err_resp = await client.get(err_url)
                        except httpx.HTTPError:
                            continue
                        if SQL_ERROR_PATTERNS.search(err_resp.text):
                            reported.add(key)
                            findings.append(_make_finding(
                                ep, param, "GET", err_payload,
                                "Error-based SQLi: a syntax-breaking payload triggered "
                                "a recognisable SQL error string in the response body.",
                                confidence="High",
                            ))
                            break

                    if key in reported:
                        continue

                    # Pass 2: boolean-based blind via GET param
                    if baseline_len is None:
                        continue
                    for true_p, false_p in PROBE_PAIRS:
                        found = await _boolean_test(
                            client, ep, param, true_p, false_p,
                            baseline_len, injection="GET",
                        )
                        if found:
                            reported.add(key)
                            findings.append(found)
                            break

            # ── POST body params ──────────────────────────────────────────
            if ep.method == "POST" and ep.params:
                for param in ep.params:
                    key = (ep.path, "post", param)
                    if key in reported:
                        continue

                    for err_payload in ERROR_PAYLOADS:
                        body = {**ep.post_body, param: err_payload}
                        try:
                            err_resp = await client.post(ep.url, data=body)
                        except httpx.HTTPError:
                            continue
                        if SQL_ERROR_PATTERNS.search(err_resp.text):
                            reported.add(key)
                            findings.append(_make_finding(
                                ep, param, "POST", err_payload,
                                "Error-based SQLi via POST body: a syntax-breaking "
                                "payload in a form field triggered a recognisable "
                                "SQL error string in the response body.",
                                confidence="High",
                            ))
                            break

            # ── Cookie params ─────────────────────────────────────────────
            for cookie_name in ep.cookie_params:
                key = (ep.path, "cookie", cookie_name)
                if key in reported:
                    continue

                # Pass 1: error-based via cookie
                for err_payload in ERROR_PAYLOADS:
                    injected_cookies = {**cookies, cookie_name: err_payload}
                    try:
                        err_resp = await client.get(
                            ep.url,
                            cookies=injected_cookies,  # type: ignore[arg-type]
                        )
                    except httpx.HTTPError:
                        continue
                    if SQL_ERROR_PATTERNS.search(err_resp.text):
                        reported.add(key)
                        findings.append(_make_finding(
                            ep, cookie_name, "COOKIE", err_payload,
                            f"Error-based SQLi via cookie '{cookie_name}': a "
                            "syntax-breaking payload in the cookie value triggered "
                            "a recognisable SQL error string in the response.",
                            confidence="High",
                        ))
                        break

                if key in reported:
                    continue

                # Pass 2: boolean-based blind via cookie
                try:
                    b1 = await client.get(ep.url)
                    b2 = await client.get(ep.url)
                    cookie_baseline = (len(b1.text) + len(b2.text)) / 2
                except httpx.HTTPError:
                    continue

                for true_p, false_p in PROBE_PAIRS:
                    true_cookies = {**cookies, cookie_name: true_p}
                    false_cookies = {**cookies, cookie_name: false_p}
                    try:
                        true_resp = await client.get(ep.url, cookies=true_cookies)  # type: ignore[arg-type]
                        false_resp = await client.get(ep.url, cookies=false_cookies)  # type: ignore[arg-type]
                    except httpx.HTTPError:
                        continue
                    tl, fl = len(true_resp.text), len(false_resp.text)
                    abs_diff = abs(fl - tl)
                    if (
                        _within(tl, cookie_baseline, 0.10)
                        and not _within(fl, tl, 0.05)
                        and abs_diff >= 5
                    ):
                        reported.add(key)
                        findings.append({
                            "id": uuid.uuid4().hex[:10],
                            "category": "sqli",
                            "severity": "High",
                            "type": "SQL Injection",
                            "endpoint": ep.path,
                            "parameter": cookie_name,
                            "method": "COOKIE",
                            "url": ep.url.split("?")[0],
                            "description": (
                                f"The '{cookie_name}' cookie value is concatenated "
                                "directly into a SQL query. A boolean-based blind "
                                "injection payload altered the response, confirming "
                                "the backend query is unsanitized."
                            ),
                            "evidence": (
                                f"Cookie {cookie_name}={true_p!r} matched baseline "
                                f"({tl} bytes, avg {cookie_baseline:.0f}); "
                                f"{cookie_name}={false_p!r} returned {fl} bytes "
                                f"(delta {abs_diff} bytes)."
                            ),
                            "confidence": "Medium",
                        })
                        break

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_baseline(client: httpx.AsyncClient, url: str) -> float | None:
    try:
        b1 = await client.get(url)
        b2 = await client.get(url)
        return (len(b1.text) + len(b2.text)) / 2
    except httpx.HTTPError:
        return None


async def _boolean_test(
    client: httpx.AsyncClient,
    ep: Endpoint,
    param: str,
    true_payload: str,
    false_payload: str,
    baseline_len: float,
    injection: str = "GET",
) -> dict | None:
    true_url = _build_test_url(ep.url, param, true_payload)
    false_url = _build_test_url(ep.url, param, false_payload)
    try:
        true_resp = await client.get(true_url)
        false_resp = await client.get(false_url)
    except httpx.HTTPError:
        return None
    tl, fl = len(true_resp.text), len(false_resp.text)
    abs_diff = abs(fl - tl)
    if _within(tl, baseline_len, 0.10) and not _within(fl, tl, 0.05) and abs_diff >= 5:
        return {
            "id": uuid.uuid4().hex[:10],
            "category": "sqli",
            "severity": "High",
            "type": "SQL Injection",
            "endpoint": ep.path,
            "parameter": param,
            "method": injection,
            "url": f"{ep.url.split('?')[0]}?{param}=",
            "description": (
                f"The '{param}' parameter is concatenated directly into a SQL query. "
                "A boolean-based blind injection payload altered the response, "
                "confirming the backend query is unsanitized."
            ),
            "evidence": (
                f"{param}={true_payload} matched the baseline response "
                f"({tl} bytes, avg baseline {baseline_len:.0f} bytes); "
                f"{param}={false_payload} returned a different response "
                f"({fl} bytes, delta {abs_diff} bytes)."
            ),
            "confidence": "Medium",
        }
    return None


def _make_finding(
    ep: Endpoint,
    param: str,
    method: str,
    payload: str,
    description: str,
    confidence: str = "High",
) -> dict:
    return {
        "id": uuid.uuid4().hex[:10],
        "category": "sqli",
        "severity": "High",
        "type": "SQL Injection",
        "endpoint": ep.path,
        "parameter": param,
        "method": method,
        "url": ep.url.split("?")[0] if method in ("COOKIE", "POST") else f"{ep.url.split('?')[0]}?{param}=",
        "description": description,
        "evidence": f"Payload {payload!r} via '{param}' triggered a recognisable SQL error in the response body.",
        "confidence": confidence,
    }


def _within(a: int | float, b: int | float, tolerance_ratio: float) -> bool:
    if b == 0:
        return a == 0
    return abs(a - b) / b <= tolerance_ratio


def _build_test_url(url: str, param: str, payload: str) -> str:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
