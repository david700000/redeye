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

# Tighten this to your actual frontend origin(s) before anything but
# local dev touches this.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
