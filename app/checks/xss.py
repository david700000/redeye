import uuid
import httpx

from ..config import XSS_MARKER, REQUEST_TIMEOUT_SECONDS
from ..crawler import Endpoint


async def check_xss(
    endpoints: list[Endpoint],
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> list[dict]:
    """
    Reflected-XSS heuristic: inject a unique marker wrapped in an HTML
    tag into each parameter (GET query params, cookie values, POST body)
    and check whether it comes back byte-for-byte unescaped in the
    response body.

    Covers:
    - GET query string parameters
    - Cookie values (e.g. PortSwigger labs that reflect cookies)
    - POST body form fields
    """
    cookies = cookies or {}
    headers = headers or {}
    findings = []
    payload = f"<{XSS_MARKER}>{XSS_MARKER}</{XSS_MARKER}>"
    reported: set[tuple[str, str, str]] = set()

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS,
        follow_redirects=True,
        cookies=cookies,
        headers=headers,
    ) as client:
        for ep in endpoints:

            # ── GET query-string params ───────────────────────────────────
            if ep.method == "GET" and ep.params:
                for param in ep.params:
                    key = (ep.path, "get", param)
                    if key in reported:
                        continue
                    test_url = _build_test_url(ep.url, param, payload)
                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue
                    if payload in resp.text:
                        reported.add(key)
                        findings.append(_make_finding(ep, param, "GET", payload))

            # ── POST body params ──────────────────────────────────────────
            if ep.method == "POST" and ep.params:
                for param in ep.params:
                    key = (ep.path, "post", param)
                    if key in reported:
                        continue
                    body = {**ep.post_body, param: payload}
                    try:
                        resp = await client.post(ep.url, data=body)
                    except httpx.HTTPError:
                        continue
                    if payload in resp.text:
                        reported.add(key)
                        findings.append(_make_finding(ep, param, "POST", payload))

            # ── Cookie params ─────────────────────────────────────────────
            for cookie_name in ep.cookie_params:
                key = (ep.path, "cookie", cookie_name)
                if key in reported:
                    continue
                injected_cookies = {**cookies, cookie_name: payload}
                try:
                    resp = await client.get(
                        ep.url,
                        cookies=injected_cookies,  # type: ignore[arg-type]
                    )
                except httpx.HTTPError:
                    continue
                if payload in resp.text:
                    reported.add(key)
                    findings.append({
                        "id": uuid.uuid4().hex[:10],
                        "category": "xss",
                        "severity": "High",
                        "type": "Reflected XSS",
                        "endpoint": ep.path,
                        "parameter": cookie_name,
                        "method": "COOKIE",
                        "url": ep.url.split("?")[0],
                        "description": (
                            f"The '{cookie_name}' cookie value is reflected in the "
                            "page response without output encoding, allowing arbitrary "
                            "markup/script execution in a victim's browser."
                        ),
                        "evidence": (
                            f"Payload {payload!r} submitted via cookie '{cookie_name}' "
                            "was returned unescaped in the response body."
                        ),
                        "confidence": "High",
                    })

    return findings


def _make_finding(ep: Endpoint, param: str, method: str, payload: str) -> dict:
    return {
        "id": uuid.uuid4().hex[:10],
        "category": "xss",
        "severity": "High",
        "type": "Reflected XSS",
        "endpoint": ep.path,
        "parameter": param,
        "method": method,
        "url": f"{ep.url.split('?')[0]}?{param}=" if method == "GET" else ep.url.split("?")[0],
        "description": (
            f"User-supplied input in the '{param}' parameter is reflected in the "
            "page response without output encoding, allowing arbitrary markup/script "
            "execution in a victim's browser."
        ),
        "evidence": (
            f"Payload {payload!r} submitted via '{param}' ({method}) was returned "
            "unescaped in the response body."
        ),
        "confidence": "High",
    }


def _build_test_url(url: str, param: str, payload: str) -> str:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
