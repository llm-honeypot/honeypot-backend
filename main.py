import json
import os
from typing import Optional

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.concurrency import run_in_threadpool

import classifier
import deception
import session_manager
from fake_data import (
    CUSTOMER_ROWS, EMPLOYEE_ROWS, FAKE_SQL_DUMP, FAKE_CONFIG,
    FAKE_PASSWD, FAKE_ENV, generate_jwt, canary_token,
)
from models import AttackType, AttackAnalysis

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


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://vaultbank-in.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FAKE_HEADERS = {
    "Server": "nginx/1.24.0",
    "X-Powered-By": "VaultBank-Core/6.4.1",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


def _client_ip(request: Request) -> str:
    return request.headers.get("X-Forwarded-For", request.client.host).split(",")[0].strip()


async def _process(
    request: Request,
    body: str = "",
    forced_type: Optional[str] = None,
    context: Optional[dict] = None,
) -> tuple[str, str, object, object]:
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

    fake_body, resp_type = await run_in_threadpool(
        deception.generate_response, analysis.attack_type.value, stage, context or {}
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


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


# ── Decoy: VaultBank login page ───────────────────────────────────────────────

LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VaultBank — NetBanking Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f1f5f9;min-height:100vh;display:flex;flex-direction:column}
.topbar{background:#b91c1c;color:#fff;font-size:11px;padding:6px 24px;display:flex;justify-content:space-between}
header{background:#003366;color:#fff;padding:14px 28px;display:flex;justify-content:space-between;align-items:center;border-bottom:3px solid #dc2626}
.brand{display:flex;align-items:center;gap:12px}
.brand-icon{width:38px;height:38px;background:#dc2626;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:16px}
.brand h1{font-size:22px;font-weight:900;letter-spacing:-0.5px}
.brand h1 span{color:#ef4444}
.brand p{font-size:9px;letter-spacing:2px;color:#94a3b8;text-transform:uppercase}
.ssl{font-size:11px;color:#86efac;display:flex;align-items:center;gap:5px}
.main{flex:1;display:flex;align-items:center;justify-content:center;padding:40px 16px;background:linear-gradient(135deg,#eff6ff 0%,#f1f5f9 100%)}
.card{background:#fff;border-radius:16px;box-shadow:0 8px 40px rgba(0,0,0,.12);padding:40px;width:420px;max-width:100%}
.card-header{margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid #f1f5f9}
.card-header h2{font-size:20px;font-weight:800;color:#003366}
.card-header p{font-size:12px;color:#64748b;margin-top:4px}
label{display:block;font-size:11px;font-weight:700;color:#374151;margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
.input-wrap{position:relative;margin-bottom:18px}
input{width:100%;padding:11px 13px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:14px;color:#0f172a;background:#f8fafc}
input:focus{outline:none;border-color:#003366;background:#fff;box-shadow:0 0 0 3px rgba(0,51,102,.08)}
button{width:100%;padding:12px;background:#dc2626;color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:800;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px}
button:hover{background:#b91c1c}
.err{color:#dc2626;font-size:12px;margin-top:12px;text-align:center;display:none}
.notice{background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:12px;font-size:11px;color:#991b1b;margin-bottom:20px;display:flex;gap:8px}
footer{background:#003366;color:#475569;font-size:11px;text-align:center;padding:12px;border-top:1px solid #1e3a5f}
footer span{color:#64748b}
</style>
</head>
<body>
<div class="topbar">
  <span>🛡️ Official NetBanking Portal &nbsp;|&nbsp; DICGC Insured up to ₹5 Lakhs</span>
  <span>Toll Free: 1800-400-VAULT (82858)</span>
</div>
<header>
  <div class="brand">
    <div class="brand-icon">V</div>
    <div><h1>VAULT<span>BANK</span></h1><p>Government Approved Digital Banking</p></div>
  </div>
  <div class="ssl">🔒 256-Bit SSL Secured</div>
</header>
<div class="main">
  <div class="card">
    <div class="card-header">
      <h2>NetBanking Login</h2>
      <p>Enter your Customer ID and password to access your account</p>
    </div>
    <div class="notice">⚠️ VaultBank never asks for OTP, MPIN or password over phone or SMS.</div>
    <form id="f">
      <div class="input-wrap">
        <label>Customer ID / Username</label>
        <input type="text" id="cid" placeholder="e.g. VB-8940192" required>
      </div>
      <div class="input-wrap">
        <label>NetBanking Password</label>
        <input type="password" id="pw" placeholder="Enter your password" required>
      </div>
      <button type="submit" id="btn">Sign In to NetBanking →</button>
      <p class="err" id="err">Invalid Customer ID or Password. Please retry.</p>
    </form>
  </div>
</div>
<footer><span>© 2026 VaultBank Ltd. All rights reserved. | RBI Regulated Entity | CIN: L65191MH1994PLC080618</span></footer>
<script>
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  const btn=document.getElementById('btn');
  btn.textContent='Authenticating...';
  const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({customer_id:document.getElementById('cid').value,password:document.getElementById('pw').value})});
  const d=await r.json();
  if(r.ok&&d.token){localStorage.setItem('vb_token',d.token);window.location.href='/dashboard';}
  else{document.getElementById('err').style.display='block';btn.textContent='Sign In to NetBanking →';}
});
</script>
</body></html>
"""

# ── Login endpoint ────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    await _process(request)
    return HTMLResponse(content=LOGIN_HTML, headers=FAKE_HEADERS)


@app.post("/api/auth/login")
async def login(request: Request):
    try:
        body_str = (await request.body()).decode()
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
        token = generate_jwt("branch_manager")
        fake_body = json.dumps({
            "token": token,
            "user": {"customer_id": "VB-8940192", "name": "Bavana Sruthi",
                     "role": "customer", "branch": "VAUL0000409"},
            "session_id": canary_token(),
        })
        resp_type = "fake_jwt"
        event, profile = await run_in_threadpool(
            session_manager.record_event, session, analysis, "POST", "/api/auth/login",
            {}, body_str[:512], ip, ua, token[:60], resp_type,
        )
        await _broadcast_event(event, profile)
        return Response(content=fake_body, media_type="application/json", headers=FAKE_HEADERS)

    event, profile = await run_in_threadpool(
        session_manager.record_event, session, analysis, "POST", "/api/auth/login",
        {}, body_str[:512], ip, ua, None, "rejected",
    )
    await _broadcast_event(event, profile)
    return JSONResponse({"error": "Invalid credentials"}, status_code=401, headers=FAKE_HEADERS)


# ── Banking data endpoints (SQL injection / exfil bait) ───────────────────────

@app.get("/api/customers")
async def get_customers(request: Request):
    body, resp_type, _, _ = await _process(request)
    if resp_type in ("benign", "rejected"):
        body = json.dumps({"data": CUSTOMER_ROWS[:5], "total": 148291, "page": 1})
    return Response(content=body, media_type="application/json", headers=FAKE_HEADERS)


@app.get("/api/customers/{customer_id}")
async def get_customer(request: Request, customer_id: str):
    body, resp_type, _, _ = await _process(request)
    if resp_type in ("benign", "rejected"):
        match = next((c for c in CUSTOMER_ROWS if c["customer_id"] == customer_id), CUSTOMER_ROWS[0])
        body = json.dumps(match)
    return Response(content=body, media_type="application/json", headers=FAKE_HEADERS)


@app.get("/api/accounts")
async def get_accounts(request: Request):
    body, resp_type, _, _ = await _process(request)
    if resp_type in ("benign", "rejected"):
        body = json.dumps({
            "data": [
                {"account_number": r["account_number"], "customer_id": r["customer_id"],
                 "type": r["account_type"], "balance_inr": r["balance_inr"],
                 "ifsc": r["branch_ifsc"], "status": r["status"]}
                for r in CUSTOMER_ROWS
            ],
            "total": 148291,
        })
    return Response(content=body, media_type="application/json", headers=FAKE_HEADERS)


@app.get("/api/accounts/{account_number}")
async def get_account(request: Request, account_number: str):
    body, resp_type, _, _ = await _process(request)
    if resp_type in ("benign", "rejected"):
        match = next((r for r in CUSTOMER_ROWS if r["account_number"] == account_number), CUSTOMER_ROWS[0])
        body = json.dumps(match)
    return Response(content=body, media_type="application/json", headers=FAKE_HEADERS)


@app.get("/api/v1/core/accounts")
async def core_accounts(request: Request):
    body, resp_type, _, _ = await _process(request)
    if resp_type in ("benign", "rejected"):
        body = json.dumps({"service": "vault-core-accounts", "version": "v4.12.8-prod",
                           "data": CUSTOMER_ROWS[:3]})
    return Response(content=body, media_type="application/json", headers=FAKE_HEADERS)


@app.get("/api/transactions")
async def get_transactions(request: Request):
    body, resp_type, _, _ = await _process(request)
    if resp_type in ("benign", "rejected"):
        body = json.dumps({
            "data": [
                {"id": "TXN-90284102", "customer_id": "VB-8940192", "amount": 325000.00,
                 "type": "credit", "merchant": "Infosys Tech Payroll", "date": "2026-09-16",
                 "status": "Completed", "ref": "CMS90281048109"},
                {"id": "TXN-90284101", "customer_id": "VB-8940192", "amount": 18450.00,
                 "type": "debit", "merchant": "Taj Mahal Palace", "date": "2026-09-15",
                 "status": "Completed", "ref": "POS-891049281"},
            ],
            "total": 9841, "page": 1,
        })
    return Response(content=body, media_type="application/json", headers=FAKE_HEADERS)


@app.get("/api/reports")
async def get_reports(request: Request):
    body, resp_type, _, _ = await _process(request)
    if resp_type in ("benign", "rejected"):
        body = json.dumps({
            "data": [
                {"id": "FIN-DR-9021", "title": "Daily Settlement Report", "rows": 48291,
                 "generated": "2026-09-17", "path": "/reports/daily/FIN-DR-9021.csv"},
                {"id": "FIN-CMPL-24", "title": "RBI Compliance Audit Q3", "rows": 1204,
                 "generated": "2026-09-01", "status": "confidential"},
                {"id": "DB-BCK-17", "title": "Database Backup Manifest", "rows": 983421,
                 "path": "/backup/db.sql"},
            ]
        })
    return Response(content=body, media_type="application/json", headers=FAKE_HEADERS)


# ── Internal services bait ─────────────────────────────────────────────────────

@app.get("/internal/services")
async def internal_services(request: Request):
    await _process(request, forced_type="dir_enum")
    return JSONResponse({
        "services": [
            {"name": "Vault Core Account Service", "id": "srv-core-acc",
             "status": "HEALTHY", "endpoint": "/api/v1/core/accounts", "latencyMs": 14},
            {"name": "Transaction Router Engine", "id": "srv-txn-router",
             "status": "HEALTHY", "endpoint": "/api/transactions", "latencyMs": 18},
            {"name": "OAuth2 / JWT Auth Guard", "id": "srv-auth-guard",
             "status": "HEALTHY", "endpoint": "/api/auth/login", "latencyMs": 9},
            {"name": "Customer & KYC Master DB", "id": "srv-cust-master",
             "status": "HEALTHY", "endpoint": "/api/customers", "latencyMs": 22},
            {"name": "Real-Time Fraud Monitoring AI", "id": "srv-fraud-ai",
             "status": "HEALTHY", "endpoint": "/internal/services/fraud", "latencyMs": 31},
        ]
    }, headers=FAKE_HEADERS)


@app.get("/internal/services/fraud")
async def fraud_service(request: Request):
    await _process(request, forced_type="ssrf")
    return JSONResponse({
        "service": "vaultbank-fraud-ai-v2",
        "model": "fraud-detection-transformer-v2.4.0",
        "status": "ACTIVE",
        "endpoint": "http://fraud-detection-service.internal:9000",
        "api_key_hint": "FraudAI-Pr0d-K3y-xZ9m...",
        "last_alert": {"customer_id": "VB-9182730", "reason": "unusual_login_pattern",
                       "score": 0.94, "timestamp": "2026-09-17T08:14:33Z"},
    }, headers=FAKE_HEADERS)


# ── Credential harvest routes ──────────────────────────────────────────────────

@app.get("/.env")
async def dotenv(request: Request):
    await _process(request, forced_type="cred_harvest")
    return PlainTextResponse(content=FAKE_ENV, headers=FAKE_HEADERS)


@app.get("/config.json")
async def config_json(request: Request):
    await _process(request, forced_type="cred_harvest")
    return Response(content=FAKE_CONFIG, media_type="application/json", headers=FAKE_HEADERS)


@app.get("/backup/db.sql")
async def backup_sql(request: Request):
    await _process(request, forced_type="cred_harvest")
    return PlainTextResponse(content=FAKE_SQL_DUMP, headers=FAKE_HEADERS)


@app.get("/etc/passwd")
async def etc_passwd(request: Request):
    await _process(request, forced_type="path_traversal")
    return PlainTextResponse(content=FAKE_PASSWD, headers=FAKE_HEADERS)


# ── Admin / recon bait ────────────────────────────────────────────────────────

@app.get("/admin/debug")
async def admin_debug(request: Request):
    await _process(request, forced_type="dir_enum")
    return JSONResponse({
        "applicationStatus": "Operational (Cluster Grade A+)",
        "serverHealth": "Optimal (Load Average 0.24, 0.18, 0.15)",
        "databaseStatus": "PostgreSQL Active-Active Primary Node 01 Connected",
        "redisCluster": "Redis Sentinel Enterprise - 6/6 Nodes Synced",
        "vaultVersion": "VaultBank Enterprise Kernel v6.4.1-patch3",
        "activeSessions": 14208,
        "environment": "production-asia-south1 (Mumbai)",
        "uptime": "148 days, 18 hours, 32 minutes",
        "node_id": "MUM-PROD-SYS01",
        "cpuUsage": "12.4%",
        "memoryUsage": "34.2 / 128.0 GB RAM",
    }, headers=FAKE_HEADERS)


# ── RCE bait ──────────────────────────────────────────────────────────────────

@app.post("/api/execute")
async def execute(request: Request):
    try:
        data = await request.json()
        cmd = data.get("cmd", data.get("command", "ls"))
    except Exception:
        cmd = "ls"
    body, _, _, _ = await _process(request, forced_type="cmd_injection", context={"cmd": cmd})
    return PlainTextResponse(content=body, headers=FAKE_HEADERS)


# ── Catch-all (dir enum / unknown probes) ─────────────────────────────────────

@app.get("/{path:path}")
async def catch_all(request: Request, path: str):
    body, resp_type, _, _ = await _process(request)
    if resp_type == "benign":
        return JSONResponse({"error": "Not Found"}, status_code=404, headers=FAKE_HEADERS)
    return Response(content=body, media_type="application/json", headers=FAKE_HEADERS)


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        profiles = await run_in_threadpool(session_manager.all_profiles)
        events = await run_in_threadpool(session_manager.recent_events)
        stats = await run_in_threadpool(session_manager.get_stats)
        await ws.send_json({
            "type": "init",
            "payload": {
                "sessions": [p.model_dump(mode="json") for p in profiles],
                "recent_events": [
                    {k: (v.value if hasattr(v, "value") else v)
                     for k, v in (e.items() if isinstance(e, dict) else e.model_dump(mode="json").items())}
                    for e in events
                ],
                "stats": stats.model_dump(),
            },
        })
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        try:
            ws_manager.disconnect(ws)
        except Exception:
            pass
