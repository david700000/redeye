import uuid
import re
import httpx

from ..config import REQUEST_TIMEOUT_SECONDS
from ..crawler import Endpoint

# (true_condition, false_condition) pairs. Tried in order per parameter;
# first pair that produces a clear true/false divergence is reported.
# Each pair leads with a plausible real value (1 / a) so the payload
# still resolves to a valid row before the boolean condition is
# ANDed on — a bare "' AND '1'='1" only works if the app happens to
# treat an empty match as equivalent to the original value, which
# most apps don't.
PROBE_PAIRS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
    # Numeric-context probes (e.g. WHERE id=1 AND 1=1)
    ("1 AND 1=1--", "1 AND 1=2--"),
    ("1 AND 1=1#", "1 AND 1=2#"),
]

# Error-based detection: if injecting a syntax-breaking payload causes
# recognisable DB error strings to appear, that's also a clear SQLi signal.
ERROR_PAYLOADS = ["'", "\"", "1'", "1\"", "1 OR 1=1--", "1'--"]

# Common SQL error signatures from MySQL, SQLite, PostgreSQL, MSSQL, Oracle
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


async def check_sqli(endpoints: list[Endpoint]) -> list[dict]:
    """
    Two-pass SQLi heuristic:

    1. Error-based: inject a quote/syntax-breaking payload and check if the
       response body contains recognisable DB error strings. Fast and reliable
       on unparameterised apps (testphp.vulnweb.com, DVWA easy mode).

    2. Boolean-based blind: send a 'true' and a 'false' conditional payload
       and compare response length/status to the baseline. Works on apps that
       suppress DB errors but still return different content for matching vs
       non-matching WHERE clauses.

    Two baseline samples are averaged to dampen per-request noise.
    Divergence is flagged only when BOTH a ratio threshold AND a minimum
    absolute byte difference are exceeded.

    This is intentionally simple — good for CTF/lab-grade apps, not a
    replacement for sqlmap on a hardened target.
    """
    findings = []
    reported_params: set[tuple[str, str]] = set()

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=True
    ) as client:
        for ep in endpoints:
            if ep.method != "GET" or not ep.params:
                continue

            # Dual baseline: average two fetches to reduce per-request noise.
            try:
                b1 = await client.get(ep.url)
                b2 = await client.get(ep.url)
            except httpx.HTTPError:
                continue
            baseline_len = (len(b1.text) + len(b2.text)) / 2

            for param in ep.params:
                if (ep.path, param) in reported_params:
                    continue

                # ── Pass 1: Error-based ─────────────────────────────────────
                for err_payload in ERROR_PAYLOADS:
                    err_url = _build_test_url(ep.url, param, err_payload)
                    try:
                        err_resp = await client.get(err_url)
                    except httpx.HTTPError:
                        continue

                    if SQL_ERROR_PATTERNS.search(err_resp.text):
                        reported_params.add((ep.path, param))
                        findings.append(
                            {
                                "id": uuid.uuid4().hex[:10],
                                "category": "sqli",
                                "severity": "High",
                                "type": "SQL Injection",
                                "endpoint": ep.path,
                                "parameter": param,
                                "method": "GET",
                                "url": f"{ep.url.split('?')[0]}?{param}=",
                                "description": (
                                    f"The '{param}' parameter is concatenated "
                                    "directly into a SQL query. A syntax-breaking "
                                    "payload triggered a database error message in "
                                    "the response, confirming the input reaches an "
                                    "unsanitised SQL statement."
                                ),
                                "evidence": (
                                    f"Payload {err_payload!r} via '{param}' "
                                    "triggered a recognisable SQL error string in "
                                    "the response body."
                                ),
                                "confidence": "High",
                            }
                        )
                        break  # error found for this param, skip boolean pass

                if (ep.path, param) in reported_params:
                    continue  # already reported via error-based

                # ── Pass 2: Boolean-based blind ─────────────────────────────
                for true_payload, false_payload in PROBE_PAIRS:
                    true_url = _build_test_url(ep.url, param, true_payload)
                    false_url = _build_test_url(ep.url, param, false_payload)

                    try:
                        true_resp = await client.get(true_url)
                        false_resp = await client.get(false_url)
                    except httpx.HTTPError:
                        continue

                    true_len = len(true_resp.text)
                    false_len = len(false_resp.text)

                    # true payload should look similar to the normal response.
                    # Use a wider 10% tolerance to absorb per-request noise.
                    true_close_to_baseline = _within(true_len, baseline_len, 0.10)

                    # false payload must diverge meaningfully from true payload:
                    # both ratio AND a minimum absolute byte floor must be met.
                    abs_diff = abs(false_len - true_len)
                    ratio_diverges = not _within(false_len, true_len, 0.05)
                    diverges_from_true = ratio_diverges and abs_diff >= 5

                    if true_close_to_baseline and diverges_from_true:
                        reported_params.add((ep.path, param))
                        findings.append(
                            {
                                "id": uuid.uuid4().hex[:10],
                                "category": "sqli",
                                "severity": "High",
                                "type": "SQL Injection",
                                "endpoint": ep.path,
                                "parameter": param,
                                "method": "GET",
                                "url": f"{ep.url.split('?')[0]}?{param}=",
                                "description": (
                                    f"The '{param}' parameter is concatenated "
                                    "directly into a SQL query. A boolean-based "
                                    "blind injection payload altered the "
                                    "response, confirming the backend query is "
                                    "unsanitized."
                                ),
                                "evidence": (
                                    f"{param}={true_payload} matched the "
                                    f"baseline response ({true_len} bytes, "
                                    f"avg baseline {baseline_len:.0f} bytes); "
                                    f"{param}={false_payload} returned a "
                                    f"different response ({false_len} bytes, "
                                    f"delta {abs_diff} bytes)."
                                ),
                                "confidence": "Medium",
                            }
                        )
                        break  # one confirmed pair is enough for this param

    return findings


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
