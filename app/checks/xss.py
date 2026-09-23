import uuid
import httpx

from ..config import XSS_MARKER, REQUEST_TIMEOUT_SECONDS
from ..crawler import Endpoint


async def check_xss(endpoints: list[Endpoint]) -> list[dict]:
    """
    Reflected-XSS heuristic: inject a unique marker wrapped in an HTML
    tag into each parameter and check whether it comes back byte-for-byte
    unescaped in the response body. That's sufficient signal on typical
    lab targets (DVWA, Juice Shop) without needing a headless browser to
    confirm actual execution.
    """
    findings = []
    payload = f"<{XSS_MARKER}>{XSS_MARKER}</{XSS_MARKER}>"

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=True
    ) as client:
        for ep in endpoints:
            if ep.method != "GET" or not ep.params:
                continue
            for param in ep.params:
                test_url = _build_test_url(ep.url, param, payload)
                try:
                    resp = await client.get(test_url)
                except httpx.HTTPError:
                    continue

                if payload in resp.text:
                    findings.append(
                        {
                            "id": uuid.uuid4().hex[:10],
                            "category": "xss",
                            "severity": "High",
                            "type": "Reflected XSS",
                            "endpoint": ep.path,
                            "parameter": param,
                            "method": "GET",
                            "url": f"{ep.url.split('?')[0]}?{param}=",
                            "description": (
                                f"User-supplied input in the '{param}' parameter is "
                                "reflected in the page response without output "
                                "encoding, allowing arbitrary markup/script "
                                "execution in a victim's browser."
                            ),
                            "evidence": (
                                f"Payload {payload} submitted via '{param}' was "
                                "returned unescaped in the response body."
                            ),
                            "confidence": "High",
                        }
                    )
    return findings


def _build_test_url(url: str, param: str, payload: str) -> str:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
