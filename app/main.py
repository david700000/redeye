import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import scans, scope, ws

app = FastAPI(
    title="Redshell API",
    description=(
        "Backend for the Redshell pentest workspace. Every scan and "
        "exploitation action is checked against an explicit lab scope "
        "before it runs — see /scope."
    ),
    version="0.1.0",
)

# Read allowed origins from env so the Render deployment can be scoped to
# the real frontend URL via the dashboard, while local dev still works with *.
_raw_origins = os.environ.get("CORS_ORIGINS", "*")
ALLOW_ORIGINS = [o.strip() for o in _raw_origins.split(",")] if _raw_origins != "*" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(scope.router)
app.include_router(ws.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
