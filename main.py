import json
import os
from contextlib import asynccontextmanager
from typing import Optional

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.concurrency import run_in_threadpool

import classifier
import deception
import session_manager
from fake_data import (
    PATIENT_ROWS, STAFF_ROWS, FAKE_SQL_DUMP, FAKE_SYSINFO,
    generate_fake_jwt, fake_shell_output,
)
from models import AttackType, AttackAnalysis, LoginRequest

# ── WebSocket connection manager ────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket):
        self._connections.remove(ws)

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self._connections:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.remove(ws)


ws_manager = ConnectionManager()


async def _broadcast_event(event, profile):
    await ws_manager.broadcast({"type": "event",          "payload": event.model_dump(mode="json")})
    await ws_manager.broadcast({"type": "profile_update", "payload": profile.model_dump(mode="json")})


# ── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

FAKE_HEADERS = {
    "Server": "Apache/2.4.41 (Ubuntu)",
    "X-Powered-By": "PHP/7.4.3",
    "X-Content-Type-Options": "nosniff",
}


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Forwarded-For", request.client.host).split(",")[0].strip()


async def _process(
    request: Request,
    body: str = "",
    forced_type: Optional[str] = None,
    context: dict | None = None,
) -> tuple[str, str, object, object]:
    """Classify → update session → generate fake response. Returns (body, resp_type, event, profile)."""
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    qs = str(request.query_params)
    path = request.url.path

    if forced_type:
        analysis = AttackAnalysis(
            attack_type=AttackType(forced_type),
            confidence=0.9,
            score=25.0,
            matched_patterns=[f"forced:{forced_type}"],
        )
    else:
        analysis = classifier.analyze_request(request.method, path, qs, body, ua)

    session = await run_in_threadpool(session_manager.get_or_create, ip, ua)
    stage = int(session.get("stage", 0))

    at_val = forced_type or analysis.attack_type.value
    fake_body, resp_type = await run_in_threadpool(
        deception.generate_response, at_val, stage, context or {}
    )

    event, profile = await run_in_threadpool(
        session_manager.record_event,
        session, analysis, request.method, path,
        dict(request.query_params), body[:512] if body else None,
        ip, ua, fake_body, resp_type,
    )

    await _broadcast_event(event, profile)

    stats = await run_in_threadpool(session_manager.get_stats)
    await ws_manager.broadcast({"type": "stats", "payload": stats.model_dump()})

    return fake_body, resp_type, event, profile


# ── Health check (ALB) ───────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


# ── Decoy: login page ────────────────────────────────────────────────────────

LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MediTrack Pro — Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f4f8;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:10px;box-shadow:0 4px 28px rgba(0,0,0,.13);padding:42px;width:390px}
.logo{text-align:center;margin-bottom:32px}
.logo h1{color:#1a56db;font-size:26px;font-weight:700;letter-spacing:-.5px}
.logo p{color:#6b7280;font-size:12px;margin-top:6px}
.logo .badge{display:inline-block;background:#dcfce7;color:#166534;font-size:10px;padding:2px 8px;border-radius:20px;margin-top:6px}
label{display:block;font-size:13px;font-weight:500;color:#374151;margin-bottom:5px}
input{width:100%;padding:10px 13px;border:1px solid #d1d5db;border-radius:6px;font-size:14px;color:#111}
input:focus{outline:none;border-color:#1a56db;box-shadow:0 0 0 3px rgba(26,86,219,.1)}
.field{margin-bottom:18px}
button{width:100%;padding:11px;background:#1a56db;color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;margin-top:4px}
button:hover{background:#1e429f}
.err{color:#dc2626;font-size:12px;margin-top:10px;display:none;text-align:center}
.footer{text-align:center;margin-top:24px;font-size:11px;color:#9ca3af}
.footer a{color:#9ca3af}
.divider{border:none;border-top:1px solid #f3f4f6;margin:20px 0}
.hint{font-size:11px;color:#9ca3af;text-align:center}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>&#x2764;&#xfe0f; MediTrack Pro</h1>
    <p>Healthcare Management System</p>
    <span class="badge">v4.2.1 — HIPAA Compliant</span>
  </div>
  <form id="f">
    <div class="field"><label>Email Address</label><input type="email" id="email" placeholder="admin@meditrack.health" required></div>
    <div class="field"><label>Password</label><input type="password" id="pw" placeholder="••••••••" required></div>
    <button type="submit">Sign In to Dashboard</button>
    <p class="err" id="err">Invalid credentials. Please try again.</p>
  </form>
  <hr class="divider">
  <p class="hint">Forgot your password? Contact IT support at ext. 2013</p>
  <div class="footer">© 2024 MediTrack Systems Inc. · <a href="#">Privacy</a> · <a href="#">Terms</a></div>
</div>
<script>
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('pw').value})});
  const d=await r.json();
  if(r.ok&&d.token){localStorage.setItem('mt_token',d.token);window.location.href='/dashboard';}
  else{document.getElementById('err').style.display='block';}
});
</script>
</body></html>
"""

DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MediTrack Pro — Patient Dashboard</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f8fafc;color:#1e293b}
header{background:#1a56db;color:#fff;padding:14px 28px;display:flex;justify-content:space-between;align-items:center}
header h1{font-size:18px;font-weight:600}
nav a{color:rgba(255,255,255,.8);text-decoration:none;margin-left:20px;font-size:14px}
nav a:hover{color:#fff}
.container{max-width:1100px;margin:0 auto;padding:24px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.stat .n{font-size:28px;font-weight:700;color:#1a56db}
.stat .l{font-size:12px;color:#6b7280;margin-top:4px}
table{width:100%;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);border-collapse:collapse}
th{background:#f8fafc;padding:12px 16px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase}
td{padding:12px 16px;font-size:13px;border-top:1px solid #f1f5f9}
tr:hover td{background:#f8fafc}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:500}
.badge.green{background:#dcfce7;color:#166534}
.badge.yellow{background:#fef9c3;color:#713f12}
.badge.red{background:#fee2e2;color:#991b1b}
</style>
</head>
<body>
<header>
  <h1>&#x2764;&#xfe0f; MediTrack Pro</h1>
  <nav>
    <a href="/dashboard">Patients</a>
    <a href="/api/staff">Staff</a>
    <a href="/api/reports">Reports</a>
    <a href="/admin/debug">System</a>
    <a href="#" onclick="localStorage.clear();location.href='/'">Logout</a>
  </nav>
</header>
<div class="container">
  <div class="stats">
    <div class="stat"><div class="n">1,247</div><div class="l">Active Patients</div></div>
    <div class="stat"><div class="n">42</div><div class="l">Staff Members</div></div>
    <div class="stat"><div class="n">89</div><div class="l">Appointments Today</div></div>
    <div class="stat"><div class="n">7</div><div class="l">Critical Cases</div></div>
  </div>
  <h2 style="margin-bottom:12px;font-size:16px">Recent Patients</h2>
  <table>
    <tr><th>ID</th><th>Name</th><th>Diagnosis</th><th>Physician</th><th>Last Visit</th><th>Status</th></tr>
""" + "\n".join(
    f'    <tr><td>{p["id"]}</td><td>{p["patient_name"]}</td>'
    f'<td>{p["primary_diagnosis"][:40]}</td>'
    f'<td>{p["attending_physician"]}</td>'
    f'<td>{p["last_visit"]}</td>'
    f'<td><span class="badge green">Active</span></td></tr>'
    for p in PATIENT_ROWS[:6]
) + """
  </table>
</div>
</body></html>
"""

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    await _process(request)
    return HTMLResponse(content=LOGIN_HTML, headers=FAKE_HEADERS)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    await _process(request)
    return HTMLResponse(content=DASHBOARD_HTML, headers=FAKE_HEADERS)


@app.post("/api/auth/login")
async def login(request: Request):
    try:
        body = await request.body()
        body_str = body.decode()
    except Exception:
        body_str = ""

    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")

    analysis = AttackAnalysis(
        attack_type=AttackType.BRUTE_FORCE,
        confidence=0.7,
        score=8.0,
        matched_patterns=["POST /api/auth/login"],
    )

    session = await run_in_threadpool(session_manager.get_or_create, ip, ua)
    stage = int(session.get("stage", 0))

    if stage >= 2:
        token = generate_fake_jwt("admin")
        fake_body = json.dumps({"token": token, "user": {"id": 42, "email": "admin@meditrack.health", "role": "super_admin"}})
        resp_type = "fake_jwt"
        event, profile = await run_in_threadpool(
            session_manager.record_event,
            session, analysis, "POST", "/api/auth/login",
            {}, body_str[:512], ip, ua, token[:60], resp_type,
        )
        await _broadcast_event(event, profile)
        return Response(
            content=fake_body,
            media_type="application/json",
            headers=FAKE_HEADERS,
        )

    event, profile = await run_in_threadpool(
        session_manager.record_event,
        session, analysis, "POST", "/api/auth/login",
        {}, body_str[:512], ip, ua, None, "rejected",
    )
    await _broadcast_event(event, profile)
    return JSONResponse(
        {"error": "Invalid credentials"},
        status_code=401,
        headers=FAKE_HEADERS,
    )


@app.get("/api/patients")
async def get_patients(request: Request, id: Optional[str] = None, page: Optional[int] = 1):
    body, resp_type, event, profile = await _process(request)
    content_type = "application/json"
    if resp_type in ("benign", "rejected"):
        body = json.dumps({"data": PATIENT_ROWS[:5], "total": 1247, "page": page, "pages": 250})
    return Response(content=body, media_type=content_type, headers=FAKE_HEADERS)


@app.get("/api/staff")
async def get_staff(request: Request):
    await _process(request)
    return JSONResponse({"data": STAFF_ROWS}, headers=FAKE_HEADERS)


@app.get("/api/reports")
async def get_reports(request: Request):
    await _process(request)
    reports = [
        {"id": "RPT-2024-11", "title": "Monthly Patient Summary", "rows": 1247, "generated": "2024-11-01"},
        {"id": "RPT-2024-Q3", "title": "Q3 Financial Report", "rows": 8821, "generated": "2024-10-01"},
        {"id": "RPT-HIPAA-24", "title": "HIPAA Compliance Audit", "rows": 342, "generated": "2024-09-15"},
        {"id": "RPT-BACKUP-14", "title": "DB Backup Manifest", "rows": 98421, "path": "/backup/db.sql"},
    ]
    return JSONResponse({"data": reports}, headers=FAKE_HEADERS)


@app.get("/.env")
async def dotenv(request: Request):
    body, _, _, _ = await _process(request, forced_type="cred_harvest")
    return PlainTextResponse(content=body, headers=FAKE_HEADERS)


@app.get("/config.json")
async def config_json(request: Request):
    body, _, _, _ = await _process(request, forced_type="cred_harvest")
    return Response(content=body, media_type="application/json", headers=FAKE_HEADERS)


@app.get("/backup/db.sql")
async def backup_sql(request: Request):
    await _process(request, forced_type="cred_harvest")
    return PlainTextResponse(content=FAKE_SQL_DUMP, headers=FAKE_HEADERS)


@app.get("/admin/debug")
async def admin_debug(request: Request):
    await _process(request, forced_type="dir_enum")
    return JSONResponse(FAKE_SYSINFO, headers=FAKE_HEADERS)


@app.post("/api/execute")
async def execute(request: Request):
    try:
        data = await request.json()
        cmd = data.get("cmd", data.get("command", "ls"))
    except Exception:
        cmd = "ls"
    body, _, _, _ = await _process(request, forced_type="cmd_injection", context={"cmd": cmd})
    return PlainTextResponse(content=body, headers=FAKE_HEADERS)


@app.get("/api/internal/setup")
async def internal_setup(request: Request):
    body, _, _, _ = await _process(request, forced_type="cred_harvest")
    return Response(content=body, media_type="application/json", headers=FAKE_HEADERS)


@app.get("/{path:path}")
async def catch_all(request: Request, path: str):
    body, resp_type, _, _ = await _process(request)
    if resp_type in ("benign",):
        return JSONResponse({"error": "Not Found"}, status_code=404, headers=FAKE_HEADERS)
    return Response(content=body, media_type="application/json", headers={**FAKE_HEADERS})


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        # Send current state on connect
        profiles = await run_in_threadpool(session_manager.all_profiles)
        events = await run_in_threadpool(session_manager.recent_events)
        stats = await run_in_threadpool(session_manager.get_stats)
        await ws.send_json({
            "type": "init",
            "payload": {
                "sessions": [p.model_dump(mode="json") for p in profiles],
                "recent_events": [
                    {k: (v.value if hasattr(v, "value") else v) for k, v in (e.items() if isinstance(e, dict) else e.model_dump(mode="json").items())}
                    for e in events
                ],
                "stats": stats.model_dump(),
            },
        })
        # Keep alive
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        try:
            ws_manager.disconnect(ws)
        except Exception:
            pass
