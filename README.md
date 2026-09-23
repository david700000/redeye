# Redsense API

FastAPI backend for the Redsense pentest workspace frontend. Runs real
reconnaissance, discovery, and vulnerability detection against
**scope-authorized targets only** — there is no path to scan or
exploit anything not explicitly on the scope list.

## Scope

Every scan is checked against `app/scope.py` before it runs. Defaults
to `localhost` and `127.0.0.1` (`app/config.py:DEFAULT_LAB_SCOPE`).
Manage the list at runtime via:

```
GET    /scope
POST   /scope        { "host": "juice-shop.local" }
DELETE /scope/{host}
```

This mirrors the frontend's Settings > Lab scope screen exactly — wire
`ScopeManager` up to these three endpoints and the two stay in sync.

Scope is in-memory right now (`app/store.py`, `app/scope.py`). Swap
both for a real datastore before this runs anywhere multi-process.

## Run it

```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Docs at `http://localhost:8000/docs`.

Point it at a real vulnerable lab app to see findings — DVWA, OWASP
Juice Shop, or WebGoat all work well for exercising the SQLi/XSS/
traversal checks. **Only ever point this at something you're
authorized to test.**

`test_target.py` in this folder is a tiny deliberately-vulnerable
Flask app (reflected XSS, string-concatenated SQL, path traversal, no
security headers) if you want something to scan without standing up
DVWA first: `pip install flask && python3 test_target.py` runs it on
`:9090`.

## Pipeline

`app/orchestrator.py` runs seven steps per scan, index-matched to the
frontend's `SCAN_STEP_DEFS` so the UI checklist and backend never
drift:

```
0 crawl       — same-host crawl (app/crawler.py)
1 discover    — endpoint list finalized
2 params      — parameters mapped
3 headers     — app/checks/headers.py
4 xss         — app/checks/xss.py   (reflected-XSS marker injection)
5 sqli        — app/checks/sqli.py  (boolean-based blind heuristic)
6 traversal   — app/checks/traversal.py
```

These are lab-grade heuristics, not a sqlmap/ZAP replacement — good
for CTF-style apps and coursework, not for hardened production
targets.

Each `Finding` returned matches the frontend's `Finding` shape
(`id, category, severity, type, endpoint, parameter, method, url,
description, evidence, confidence`) field-for-field, so
`buildMockFindings()` in the frontend can be deleted once this is
wired up rather than reshaped.

## API

```
POST   /scans              -> starts a scan (202, returns scan_id), 403 if target out of scope
GET    /scans               -> scan history
GET    /scans/{id}           -> scan status/result
WS     /ws/scans/{id}         -> live progress events while a scan runs
GET    /health
```

### WebSocket event shape

```json
{"type": "step", "index": 4, "status": "active"}
{"type": "log", "line": "Reflected input on /search"}
{"type": "result", "findings": [...], "duration_ms": 12400, "endpoints_discovered": 24, "parameters_mapped": 17}
{"type": "error", "message": "..."}
```

## Frontend integration

`vuln-scanner-ui.jsx` is already wired to this API — no mock data left
in it. It expects the backend at `http://localhost:8000` (see
`API_BASE` near the top of the file if you're running it elsewhere).
On load it fetches `/scope` and `/scans`; on Start Scan it POSTs
`/scans` then opens the `/ws/scans/{id}` socket and streams step/log
events into the same progress UI you already saw with the mock.

A 403 (target out of scope) or a dropped WebSocket surfaces as an
inline error on the scan config card rather than failing silently.

## Deliberately not built yet

- **Auth** — no user/session model. Add before this is anything but
  local.
- **Persistence** — scans and scope live in process memory
  (`app/store.py`). Fine for dev, gone on restart.
- **Exploitation execution** — the frontend's Exploit tab is guided
  *text* (an AI-written walkthrough the tester runs manually), and
  this backend does not change that. There's intentionally no
  `/exploit` endpoint that fires payloads automatically — that's a
  much bigger scope/consent problem than detection is, and worth its
  own design pass rather than bolting on now.
- **Report generation** — `POST /scans/{id}/report` is the natural
  next endpoint once the frontend's "Generate Report" button needs a
  backend.
