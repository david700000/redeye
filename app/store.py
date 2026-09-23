"""
In-memory scan store + a tiny per-scan pub/sub so the WebSocket router
can stream progress events to whichever clients are subscribed.

Swap this for a real datastore (Postgres, Redis for the event bus)
once there's more than one process — everything else in the app only
talks to the functions below, not to a dict directly.
"""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

_scans: dict[str, dict] = {}
_subscribers: dict[str, list[asyncio.Queue]] = {}


def create_scan(target: str, profile: str) -> dict:
    scan_id = uuid.uuid4().hex[:12]
    scan = {
        "id": scan_id,
        "target": target,
        "profile": profile,
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": None,
        "endpoints_discovered": 0,
        "parameters_mapped": 0,
        "findings": [],
    }
    _scans[scan_id] = scan
    _subscribers[scan_id] = []
    return scan


def get_scan(scan_id: str) -> Optional[dict]:
    return _scans.get(scan_id)


def list_scans() -> list[dict]:
    return sorted(_scans.values(), key=lambda s: s["created_at"], reverse=True)


def update_scan(scan_id: str, **fields) -> None:
    if scan_id in _scans:
        _scans[scan_id].update(fields)


def subscribe(scan_id: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(scan_id, []).append(q)
    return q


def unsubscribe(scan_id: str, q: asyncio.Queue) -> None:
    if scan_id in _subscribers and q in _subscribers[scan_id]:
        _subscribers[scan_id].remove(q)


async def publish(scan_id: str, event: dict) -> None:
    for q in _subscribers.get(scan_id, []):
        await q.put(event)
