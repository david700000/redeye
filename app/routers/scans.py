import asyncio

from fastapi import APIRouter, HTTPException

from .. import store
from ..models import ScanRequest, ScanResult, ScanSummary, ScanStatus
from ..orchestrator import run_scan
from ..scope import is_in_scope, host_of

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanResult, status_code=202)
async def start_scan(req: ScanRequest):
    if not is_in_scope(req.target):
        raise HTTPException(
            status_code=403,
            detail=(
                f"'{host_of(req.target)}' is outside the authorized lab scope. "
                "Add it via /scope before scanning."
            ),
        )

    scan = store.create_scan(req.target, req.profile.value)
    asyncio.create_task(run_scan(scan["id"], req.target, req.profile.value))
    return scan


@router.get("", response_model=list[ScanSummary])
async def list_scans():
    scans = store.list_scans()
    return [
        {**s, "finding_count": len(s["findings"])} for s in scans
    ]


@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {**scan, "finding_count": len(scan["findings"])}
