from fastapi import APIRouter

from .. import scope as scope_module
from ..models import ScopeEntry, ScopeList

router = APIRouter(prefix="/scope", tags=["scope"])


@router.get("", response_model=ScopeList)
async def get_scope():
    return {"hosts": scope_module.get_scope()}


@router.post("", response_model=ScopeList)
async def add_scope(entry: ScopeEntry):
    return {"hosts": scope_module.add_to_scope(entry.host)}


@router.delete("/{host}", response_model=ScopeList)
async def remove_scope(host: str):
    return {"hosts": scope_module.remove_from_scope(host)}
