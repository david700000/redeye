import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import store

router = APIRouter()


@router.websocket("/ws/scans/{scan_id}")
async def scan_events(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    scan = store.get_scan(scan_id)
    if not scan:
        await websocket.send_json({"type": "error", "message": "Scan not found"})
        await websocket.close()
        return

    # Replay current status immediately so a client that connects
    # slightly late (or reconnects) isn't stuck waiting.
    if scan["status"] == "completed":
        await websocket.send_json(
            {
                "type": "result",
                "findings": scan["findings"],
                "duration_ms": scan["duration_ms"],
                "endpoints_discovered": scan["endpoints_discovered"],
                "parameters_mapped": scan["parameters_mapped"],
            }
        )
        await websocket.close()
        return

    queue = store.subscribe(scan_id)
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
            if event["type"] in ("result", "error"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        store.unsubscribe(scan_id, queue)
