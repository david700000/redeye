"""
Minimal same-host crawler used for the Recon and Discovery phases.

Not trying to be exhaustive — depth- and page-capped, same-origin only,
GET requests only. Good enough to map endpoints + parameters on a small
lab target (DVWA, Juice Shop, a local dev app, etc.).
"""

from urllib.parse import urljoin, urlparse, parse_qs
import httpx
from bs4 import BeautifulSoup

from .config import CRAWL_MAX_PAGES, CRAWL_MAX_DEPTH, REQUEST_TIMEOUT_SECONDS


class Endpoint:
    def __init__(self, url: str, method: str = "GET"):
        self.url = url
        self.method = method
        parsed = urlparse(url)
        self.path = parsed.path or "/"
        self.params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    def __repr__(self):
        return f"<Endpoint {self.method} {self.path} params={self.params}>"


async def crawl(base_url: str) -> list[Endpoint]:
    """BFS crawl starting at base_url, staying on the same host."""
    base_host = urlparse(base_url).netloc
    seen: set[str] = set()
    endpoints: dict[str, Endpoint] = {}
    queue: list[tuple[str, int]] = [(base_url, 0)]

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=True
    ) as client:
        while queue and len(seen) < CRAWL_MAX_PAGES:
            url, depth = queue.pop(0)
            if url in seen or depth > CRAWL_MAX_DEPTH:
                continue
            seen.add(url)

            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                continue

            ep_key = f"GET {urlparse(url).path}?{urlparse(url).query}"
            endpoints[ep_key] = Endpoint(url, "GET")

            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                if urlparse(link).netloc == base_host and link not in seen:
                    queue.append((link, depth + 1))

            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = (form.get("method") or "GET").upper()
                if urlparse(action).netloc != base_host:
                    continue
                inputs = [
                    i.get("name")
                    for i in form.find_all(["input", "textarea", "select"])
                    if i.get("name")
                ]
                if method == "GET":
                    query = "&".join(f"{name}=" for name in inputs)
                    form_url = action + ("?" + query if query else "")
                    endpoints[f"GET {urlparse(form_url).path}?{query}"] = Endpoint(
                        form_url, "GET"
                    )
                else:
                    ep = Endpoint(action, "POST")
                    ep.params = inputs
                    endpoints[f"POST {urlparse(action).path}"] = ep

    return list(endpoints.values())


def unique_parameters(endpoints: list[Endpoint]) -> int:
    combos = {(e.path, p) for e in endpoints for p in e.params}
    return len(combos)
