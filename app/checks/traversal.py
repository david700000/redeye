import uuid
import httpx

from ..config import REQUEST_TIMEOUT_SECONDS, TRAVERSAL_TARGETS
from ..crawler import Endpoint

# Parameter names likely to be used for file access — checked first so
# we don't waste requests probing every parameter on every endpoint.
FILE_LIKE_PARAM_HINTS = ["file", "path", "page", "doc", "template", "include", "dir"]


async def check_traversal(endpoints: list[Endpoint]) -> list[dict]:
    findings = []

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=True
    ) as client:
        for ep in endpoints:
            if ep.method != "GET" or not ep.params:
                continue

            candidate_params = [
                p
                for p in ep.params
                if any(hint in p.lower() for hint in FILE_LIKE_PARAM_HINTS)
            ] or ep.params  # fall back to trying all params if none look file-like

            for param in candidate_params:
                for target in TRAVERSAL_TARGETS:
                    test_url = _build_test_url(ep.url, param, target["payload"])
                    try:
                        resp = await client.get(test_url)
                    except httpx.HTTPError:
                        continue

                    if resp.status_code == 200 and target["signature"] in resp.text:
                        findings.append(
                            {
                                "id": uuid.uuid4().hex[:10],
                                "category": "traversal",
                                "severity": "Medium",
                                "type": "Directory Traversal",
                                "endpoint": ep.path,
                                "parameter": param,
                                "method": "GET",
                                "url": f"{ep.url.split('?')[0]}?{param}=",
                                "description": (
                                    f"The '{param}' parameter accepts relative "
                                    "path sequences that escape the intended "
                                    "directory, exposing files outside the web "
                                    "root."
                                ),
                                "evidence": (
                                    f"{param}={target['payload']} returned "
                                    f"content matching {target['label']}."
                                ),
                                "confidence": "Medium",
                            }
                        )
                        break  # one confirmed target file is enough per param
    return findings


def _build_test_url(url: str, param: str, payload: str) -> str:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
