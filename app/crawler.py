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
        parsed_q = parse_qs(parsed.query, keep_blank_values=True)
        self.params = list(parsed_q.keys())
        # Original values so checks can append payloads instead of replacing them.
        # e.g. category=Gifts → {"category": "Gifts"} → inject as "Gifts' AND '1'='1"
        self.param_values: dict[str, str] = {k: v[0] if v else "" for k, v in parsed_q.items()}
        # For POST endpoints, params holds form field names.
        # cookie_params holds cookie key names to test for injection.
        self.cookie_params: list[str] = []
        # POST body stored as a dict for form-encoded POST replay
        self.post_body: dict[str, str] = {}

    def __repr__(self):
        return f"<Endpoint {self.method} {self.path} params={self.params} cookies={self.cookie_params}>"


async def crawl(
    base_url: str,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> list["Endpoint"]:
    """BFS crawl starting at base_url, staying on the same host.

    Accepts optional cookies/headers for authenticated crawling (e.g. PortSwigger labs).
    Cookie keys from the session are exposed on every endpoint as cookie_params so
    the vulnerability checks can inject into them.
    """
    cookies = cookies or {}
    headers = headers or {}
    base_host = urlparse(base_url).netloc
    seen: set[str] = set()
    endpoints: dict[str, Endpoint] = {}
    queue: list[tuple[str, int]] = [(base_url, 0)]

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT_SECONDS,
        follow_redirects=True,
        cookies=cookies,
        headers=headers,
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
            ep = Endpoint(url, "GET")
            # Expose session cookie keys so checks can inject into them
            ep.cookie_params = list(cookies.keys())
            endpoints[ep_key] = ep

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
                    form_ep = Endpoint(form_url, "GET")
                    form_ep.cookie_params = list(cookies.keys())
                    endpoints[f"GET {urlparse(form_url).path}?{query}"] = form_ep
                else:
                    ep_post = Endpoint(action, "POST")
                    ep_post.params = inputs
                    ep_post.cookie_params = list(cookies.keys())
                    ep_post.post_body = {name: "" for name in inputs}
                    endpoints[f"POST {urlparse(action).path}"] = ep_post

    return list(endpoints.values())


def unique_parameters(endpoints: list[Endpoint]) -> int:
    combos = {(e.path, p) for e in endpoints for p in e.params}
    return len(combos)
