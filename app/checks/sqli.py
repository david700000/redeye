import uuid
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
]


async def check_sqli(endpoints: list[Endpoint]) -> list[dict]:
    """
    Boolean-based blind SQLi heuristic: for each parameter, send a
    'true' and a 'false' conditional payload and compare response
    length/status to the baseline. A parameter that's just treated as
    inert text will respond the same way to both; one that reaches a
    real SQL WHERE clause typically won't.

    Two baseline samples are averaged to dampen page-level noise
    (dynamic timestamps, CSRF tokens, session data, etc.) that caused
    single-sample comparisons to be flaky across repeated scans.

    Divergence is flagged only when BOTH a ratio threshold AND a minimum
    absolute byte difference are exceeded, preventing false positives on
    large pages where a small fluctuation could cross the ratio threshold.

    This is intentionally simple — good for CTF/lab-grade apps, not a
    replacement for sqlmap on a hardened target.
    """
    findings = []

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
