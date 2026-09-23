"""
Runs one scan end-to-end as a background task and publishes progress
events the WebSocket router forwards to the frontend. Step ids here
match config.SCAN_STEPS index-for-index with the frontend's
SCAN_STEP_DEFS, so the UI checklist and the backend pipeline never
drift out of sync.
"""

import asyncio
import time
import httpx

from . import store
from .config import SCAN_STEPS, REQUEST_TIMEOUT_SECONDS
from .crawler import crawl, unique_parameters, Endpoint
from .checks.headers import check_headers
from .checks.ssl_check import check_ssl
from .checks.xss import check_xss
from .checks.sqli import check_sqli
from .checks.traversal import check_traversal

STEP_INDEX = {s["id"]: i for i, s in enumerate(SCAN_STEPS)}

# Common paths to probe as synthetic endpoints when the crawl finds no
# query-string parameters (handles JSON APIs, SPAs, and minimal lab targets).
COMMON_PROBE_PATHS = [
    "/search?q=test",
    "/products?id=1",
    "/item?id=1",
    "/user?id=1",
    "/page?id=1",
    "/file?path=index",
    "/view?page=home",
    "/article?id=1",
    "/news?id=1",
    "/category?id=1",
    "/index?page=1",
]


async def _is_reachable(target: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            await client.get(target)
            return True
    except Exception:
        return False


async def run_scan(scan_id: str, target: str, profile: str) -> None:
    started = time.monotonic()
    store.update_scan(scan_id, status="running")

    async def log(line: str):
        await store.publish(scan_id, {"type": "log", "line": line})

    try:
        # Reachability check
        await log(f"Checking reachability of {target}...")
        reachable = await _is_reachable(target)
        if not reachable:
            await log(f"WARNING: Target did not respond - results may be incomplete")
        else:
            await log(f"Target responded OK")

        # Crawl
        await _step(scan_id, "crawl", "active")
        endpoints = await crawl(target)
        await log(f"Crawl complete: {len(endpoints)} endpoint(s) found")
        for ep in endpoints[:8]:
            param_str = f" [{', '.join(ep.params)}]" if ep.params else " [no params]"
            await log(f"  {ep.method} {ep.path}{param_str}")
        if len(endpoints) > 8:
            await log(f"  ... and {len(endpoints) - 8} more")
        await _step(scan_id, "crawl", "done")

        # Discovery
        await _step(scan_id, "discover", "active")
        await _step(scan_id, "discover", "done")

        # Parameter mapping
        await _step(scan_id, "params", "active")
        param_count = unique_parameters(endpoints)
        store.update_scan(
            scan_id,
            endpoints_discovered=len(endpoints),
            parameters_mapped=param_count,
        )
        await log(f"Parameters mapped: {param_count}")

        # When the crawl found no query-string parameters, add common probe
        # paths so XSS/SQLi/traversal still run (handles JSON APIs and SPAs).
        param_endpoints = [e for e in endpoints if e.params]
        if not param_endpoints and reachable:
            base = target.rstrip("/")
            await log("No query-string parameters found via crawl")
            await log(f"Probing {len(COMMON_PROBE_PATHS)} common paths for vulnerability checks")
            for path in COMMON_PROBE_PATHS:
                ep = Endpoint(base + path)
                endpoints.append(ep)

        await _step(scan_id, "params", "done")

        # Recompute after the fallback probe paths may have been added.
        probe_eps = [e for e in endpoints if e.params]

        # Security headers
        await _step(scan_id, "headers", "active")
        await log("Checking security response headers...")
        header_findings = await check_headers(target)
        if header_findings:
            missing = [f["type"].replace("Missing Security Header: ", "") for f in header_findings]
            await log(f"Missing headers ({len(header_findings)}): {', '.join(missing)}")
        else:
            await log("All required security headers present")
        await _step(scan_id, "headers", "done")

        # SSL/TLS
        await _step(scan_id, "ssl", "active")
        await log("Auditing SSL/TLS configuration...")
        ssl_findings = await check_ssl(target)
        if ssl_findings:
            for f in ssl_findings:
                await log(f"FOUND: {f['type']} at {f['url']}")
        else:
            await log("SSL/TLS configuration looks healthy")
        await _step(scan_id, "ssl", "done")

        # XSS
        await _step(scan_id, "xss", "active")
        await log(f"Testing {len(probe_eps)} parameterised endpoint(s) for XSS...")
        xss_findings = await check_xss(endpoints)
        for f in xss_findings:
            await log(f"FOUND: Reflected XSS on {f['endpoint']}?{f['parameter']}=")
        if not xss_findings:
            await log("No XSS reflections detected")
        await _step(scan_id, "xss", "done")

        # SQLi
        await _step(scan_id, "sqli", "active")
        await log(f"Testing {len(probe_eps)} parameterised endpoint(s) for SQL injection...")
        sqli_findings = await check_sqli(endpoints)
        for f in sqli_findings:
            await log(f"FOUND: Boolean divergence on {f['endpoint']}?{f['parameter']}=")
        if not sqli_findings:
            await log("No SQL injection signals detected")
        await _step(scan_id, "sqli", "done")

        # Traversal
        await _step(scan_id, "traversal", "active")
        await log("Testing path parameters for directory traversal...")
        traversal_findings = await check_traversal(endpoints)
        for f in traversal_findings:
            await log(f"FOUND: Path traversal on {f['endpoint']}?{f['parameter']}=")
        if not traversal_findings:
            await log("No path traversal detected")
        await _step(scan_id, "traversal", "done")

        # Finalise
        all_findings = (
            sqli_findings + xss_findings + traversal_findings + header_findings + ssl_findings
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        await log(
            f"Scan complete: {len(all_findings)} finding(s) in {duration_ms / 1000:.1f}s"
        )

        store.update_scan(
            scan_id,
            status="completed",
            duration_ms=duration_ms,
            findings=all_findings,
        )
        await store.publish(
            scan_id,
            {
                "type": "result",
                "findings": all_findings,
                "duration_ms": duration_ms,
                "endpoints_discovered": len(endpoints),
                "parameters_mapped": param_count,
            },
        )

    except Exception as exc:  # noqa: BLE001
        store.update_scan(scan_id, status="failed")
        await store.publish(scan_id, {"type": "error", "message": str(exc)})


async def _step(scan_id: str, step_id: str, status: str) -> None:
    await store.publish(
        scan_id, {"type": "step", "index": STEP_INDEX[step_id], "status": status}
    )
