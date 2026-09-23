import uuid
import httpx

from ..config import REQUIRED_HEADERS, REQUEST_TIMEOUT_SECONDS


async def check_headers(
    target: str,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> list[dict]:
    cookies = cookies or {}
    headers = headers or {}
    findings = []
    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS,
        follow_redirects=True,
        cookies=cookies,
        headers=headers,
    ) as client:
        try:
            resp = await client.get(target)
        except httpx.HTTPError:
            return findings

        present = {k.lower() for k in resp.headers.keys()}

        for spec in REQUIRED_HEADERS:
            if spec["header"] not in present:
                findings.append(
                    {
                        "id": uuid.uuid4().hex[:10],
                        "category": "headers",
                        "severity": "Low",
                        "type": f"Missing Security Header: {spec['name']}",
                        "endpoint": "/",
                        "parameter": "—",
                        "method": "GET",
                        "url": target.rstrip("/") + "/",
                        "description": spec["description"],
                        "evidence": f"No '{spec['header']}' header present in response.",
                        "confidence": "High",
                    }
                )
    return findings
