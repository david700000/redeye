import uuid
import re
import httpx

from ..config import REQUEST_TIMEOUT_SECONDS
from ..crawler import Endpoint

# ── Append-mode probe pairs ────────────────────────────────────────────────
# These are APPENDED to the original parameter value, not used as a full
# replacement. This is critical for real targets where the original value
# matters (e.g. category=Gifts → Gifts' AND '1'='1 vs Gifts' AND '1'='2).
APPEND_PROBE_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),          # single-quote string context
    ("' AND 1=1--", "' AND 1=2--"),             # single-quote + comment
    ("' AND 1=1#", "' AND 1=2#"),               # MySQL hash comment
    ('" AND "1"="1', '" AND "1"="2'),            # double-quote string context
    (" AND 1=1--", " AND 1=2--"),               # unquoted numeric context
    (" AND 1=1", " AND 1=2"),                   # unquoted numeric (no comment)
]

# ── Replace-mode probe pairs ───────────────────────────────────────────────
# Tried when the original value is empty ("") or a plain integer string.
REPLACE_PROBE_PAIRS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
    ("1 AND 1=1--", "1 AND 1=2--"),
    ("1 AND 1=1#", "1 AND 1=2#"),
]

# ── Error-based suffixes ───────────────────────────────────────────────────
# Appended to original value; trigger a syntax error the DB reports back.
ERROR_SUFFIXES = ["'", '"', "'--", '"--', "' OR '1'='1", '" OR "1"="1']

# ── SQL error signatures ───────────────────────────────────────────────────
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
    Universal SQLi heuristic (GET params, POST body, cookie values).

    For every parameter across all input methods (GET, POST, COOKIES),
    it runs three passes:
    1. Error-based   — append a syntax-breaking suffix to the ORIGINAL value
                       and look for DB error strings in the response.
    2. Boolean append  — append true/false conditions to the ORIGINAL value
                       and compare response lengths to the baseline.
    3. Boolean replace — replace the value entirely with true/false payloads
                       and compare response lengths to the baseline.
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
                    orig = ep.param_values.get(param, "")

                    # Pass 1: error-based
                    for suffix in ERROR_SUFFIXES:
                        err_url = _build_test_url(ep.url, param, orig + suffix)
                        try:
                            err_resp = await client.get(err_url)
                        except httpx.HTTPError:
                            continue
                        if SQL_ERROR_PATTERNS.search(err_resp.text):
                            reported.add(key)
                            findings.append(_make_finding(
                                ep, param, "GET",
                                orig + suffix,
                                f"The '{param}' parameter is concatenated into a SQL "
                                "query without sanitization. A syntax-breaking payload "
                                "triggered a recognisable SQL error string in the response.",
                                confidence="High",
                            ))
                            break

                    if key in reported or baseline_len is None:
                        continue

                    # Pass 2a: boolean-blind — append mode
                    for true_sfx, false_sfx in APPEND_PROBE_PAIRS:
                        found = await _boolean_test(
                            client, ep, param,
                            orig + true_sfx, orig + false_sfx,
                            baseline_len, injection="GET",
                        )
                        if found:
                            reported.add(key)
                            findings.append(found)
                            break

                    if key in reported:
                        continue

                    # Pass 2b: boolean-blind — replace mode
                    for true_p, false_p in REPLACE_PROBE_PAIRS:
                        found = await _boolean_test(
                            client, ep, param,
                            true_p, false_p,
                            baseline_len, injection="GET",
                        )
                        if found:
                            reported.add(key)
                            findings.append(found)
                            break

            # ── POST body params ──────────────────────────────────────────
            if ep.method == "POST" and ep.params:
                baseline_len = await _post_baseline(client, ep.url, ep.post_body)
                
                for param in ep.params:
                    key = (ep.path, "post", param)
                    if key in reported:
                        continue
                    orig = ep.post_body.get(param, "")

                    # Pass 1: error-based
                    for suffix in ERROR_SUFFIXES:
                        body = {**ep.post_body, param: orig + suffix}
                        try:
                            err_resp = await client.post(ep.url, data=body)
                        except httpx.HTTPError:
                            continue
                        if SQL_ERROR_PATTERNS.search(err_resp.text):
                            reported.add(key)
                            findings.append(_make_finding(
                                ep, param, "POST",
                                orig + suffix,
                                f"The '{param}' POST parameter is concatenated into a "
                                "SQL query. A syntax-breaking payload triggered a "
                                "recognisable SQL error in the response body.",
                                confidence="High",
                            ))
                            break
                            
                    if key in reported or baseline_len is None:
                        continue
                        
                    # Pass 2a: boolean-blind — append mode
                    for true_sfx, false_sfx in APPEND_PROBE_PAIRS:
                        found = await _boolean_post_test(
                            client, ep, param,
                            orig + true_sfx, orig + false_sfx,
                            baseline_len,
                        )
                        if found:
                            reported.add(key)
                            findings.append(found)
                            break

                    if key in reported:
                        continue

                    # Pass 2b: boolean-blind — replace mode
                    for true_p, false_p in REPLACE_PROBE_PAIRS:
                        found = await _boolean_post_test(
                            client, ep, param,
                            true_p, false_p,
                            baseline_len,
                        )
                        if found:
                            reported.add(key)
                            findings.append(found)
                            break


            # ── Cookie params ─────────────────────────────────────────────
            for cookie_name in ep.cookie_params:
                key = (ep.path, "cookie", cookie_name)
                if key in reported:
                    continue
                orig = cookies.get(cookie_name, "")
                baseline_len = await _get_baseline(client, ep.url)

                # Pass 1: error-based via cookie (append to original value)
                for suffix in ERROR_SUFFIXES:
                    injected = {**cookies, cookie_name: orig + suffix}
                    try:
                        err_resp = await client.get(
                            ep.url,
                            cookies=injected,  # type: ignore[arg-type]
                        )
                    except httpx.HTTPError:
                        continue
                    if SQL_ERROR_PATTERNS.search(err_resp.text):
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
                                "into a SQL query without sanitization. A "
                                "syntax-breaking payload triggered a recognisable "
                                "SQL error string in the response."
                            ),
                            "evidence": (
                                f"Appending {suffix!r} to the '{cookie_name}' cookie "
                                "value triggered a recognisable SQL error in the response body."
                            ),
                            "confidence": "High",
                        })
                        break

                if key in reported or baseline_len is None:
                    continue

                # Pass 2a: boolean-blind via cookie (append to original value)
                for true_sfx, false_sfx in APPEND_PROBE_PAIRS:
                    found = await _boolean_cookie_test(
                        client, ep, cookie_name, cookies,
                        orig + true_sfx, orig + false_sfx,
                        baseline_len
                    )
                    if found:
                        reported.add(key)
                        findings.append(found)
                        break
                        
                if key in reported:
                    continue
                    
                # Pass 2b: boolean-blind via cookie (replace mode)
                for true_p, false_p in REPLACE_PROBE_PAIRS:
                    found = await _boolean_cookie_test(
                        client, ep, cookie_name, cookies,
                        true_p, false_p,
                        baseline_len
                    )
                    if found:
                        reported.add(key)
                        findings.append(found)
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
        
async def _post_baseline(client: httpx.AsyncClient, url: str, body: dict) -> float | None:
    try:
        b1 = await client.post(url, data=body)
        b2 = await client.post(url, data=body)
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
                f"True payload matched baseline ({tl} bytes, avg {baseline_len:.0f}); "
                f"false payload returned {fl} bytes (delta {abs_diff} bytes). "
                f"True: {true_payload!r}, False: {false_payload!r}"
            ),
            "confidence": "Medium",
        }
    return None

async def _boolean_post_test(
    client: httpx.AsyncClient,
    ep: Endpoint,
    param: str,
    true_payload: str,
    false_payload: str,
    baseline_len: float,
) -> dict | None:
    try:
        true_resp = await client.post(ep.url, data={**ep.post_body, param: true_payload})
        false_resp = await client.post(ep.url, data={**ep.post_body, param: false_payload})
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
            "method": "POST",
            "url": ep.url.split("?")[0],
            "description": (
                f"The '{param}' POST parameter is concatenated directly into a SQL query. "
                "A boolean-based blind injection payload altered the response, "
                "confirming the backend query is unsanitized."
            ),
            "evidence": (
                f"True payload matched baseline ({tl} bytes, avg {baseline_len:.0f}); "
                f"false payload returned {fl} bytes (delta {abs_diff} bytes). "
                f"True: {true_payload!r}, False: {false_payload!r}"
            ),
            "confidence": "Medium",
        }
    return None

async def _boolean_cookie_test(
    client: httpx.AsyncClient,
    ep: Endpoint,
    param: str,
    cookies: dict,
    true_payload: str,
    false_payload: str,
    baseline_len: float,
) -> dict | None:
    try:
        true_resp = await client.get(ep.url, cookies={**cookies, param: true_payload})
        false_resp = await client.get(ep.url, cookies={**cookies, param: false_payload})
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
            "method": "COOKIE",
            "url": ep.url.split("?")[0],
            "description": (
                f"The '{param}' cookie is concatenated directly into a SQL query. "
                "A boolean-based blind injection payload altered the response, "
                "confirming the backend query is unsanitized."
            ),
            "evidence": (
                f"True payload matched baseline ({tl} bytes, avg {baseline_len:.0f}); "
                f"false payload returned {fl} bytes (delta {abs_diff} bytes). "
                f"True: {true_payload!r}, False: {false_payload!r}"
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
