"""AI SOC Platform API — FastAPI Backend.

Full-featured API with:
- Log ingestion with rate limiting
- Alert, incident, and response management
- Tiered autonomous response with approval gates
- Immutable audit logging
- JWT authentication with RBAC
- AI chat with NL-to-SQL
- PDF reports and weekly digests
- Draft deterrence emails with review workflow
- WebSocket real-time feed
- Health checks and metrics
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from models import TelemetryLog, ChatRequest, LoginRequest, RegisterRequest, VerdictRequest, ApprovalRequest, APIKeyCreate
from database import init_db, get_db
from detection import check_for_abuse, calculate_fingerprint, update_entity_baselines
from threat_intel import enrich_ip
from chat import handle_chat
from pdf_report import generate_pdf_report
from digest_report import generate_digest
from agentic_investigation import build_attack_graph
from auth import authenticate, register_user, verify_token, get_user_from_token, has_permission
from rate_limiter import IngestRateLimiter
from response import ResponseEngine
import uvicorn
import json
import asyncio
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()

# ── Rate Limiter ──
_rate_limiter = IngestRateLimiter(max_requests=500, window_seconds=60)
_response_engine = ResponseEngine()


# ── Lifespan ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Start background tasks
    asyncio.create_task(_baseline_updater())
    asyncio.create_task(_block_expiry_checker())
    asyncio.create_task(_rate_limiter_cleanup())
    yield


app = FastAPI(title="AI SOC Platform API", lifespan=lifespan)

import os

# Parse ALLOWED_ORIGINS from env, defaulting to local access if not set
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "*")
if allowed_origins_env == "*":
    origins = ["*"]
else:
    origins = [o.strip() for o in allowed_origins_env.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Background Tasks ──

async def _baseline_updater():
    """Update entity baselines every hour."""
    while True:
        await asyncio.sleep(3600)  # 1 hour
        try:
            update_entity_baselines()
        except Exception as e:
            print(f"[BASELINE] Update failed: {e}")


async def _block_expiry_checker():
    """Check for expired blocks every 5 minutes."""
    while True:
        await asyncio.sleep(300)  # 5 minutes
        try:
            _response_engine.check_expired_blocks()
        except Exception as e:
            print(f"[EXPIRY] Check failed: {e}")


async def _rate_limiter_cleanup():
    """Clean up stale rate limiter entries every 10 minutes."""
    while True:
        await asyncio.sleep(600)
        try:
            _rate_limiter.cleanup()
        except Exception as e:
            print(f"[RATE LIMITER] Cleanup failed: {e}")


# ── Auth Dependency ──

def get_current_user(request: Request) -> dict:
    """Extract and verify user from Authorization header. Returns None for unauthenticated."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:]
    user = get_user_from_token(token)
    return user


def require_auth(request: Request) -> dict:
    """Require authentication. Raises 401 if not authenticated."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_role(role: str):
    """Dependency factory for role-based access control."""
    def _check(request: Request):
        user = require_auth(request)
        if not has_permission(user['role'], role):
            raise HTTPException(status_code=403, detail=f"Insufficient permissions. Required: {role}")
        return user
    return _check


# ── WebSocket Connection Manager ──
connected_clients: list[WebSocket] = []


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(ws)


def broadcast_event(data: dict):
    message = json.dumps(data, default=str)
    disconnected = []
    for ws in connected_clients:
        try:
            asyncio.get_event_loop().create_task(ws.send_text(message))
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        connected_clients.remove(ws)


# ══════════════════════════════════════════════════════════════
#  AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.post("/auth/login")
async def login(req: LoginRequest):
    result = authenticate(req.username, req.password)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return result


@app.post("/auth/register")
async def register(req: RegisterRequest, user: dict = Depends(require_role("manage_users"))):
    result = register_user(req.username, req.password, req.role)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/auth/me")
async def get_me(user: dict = Depends(require_auth)):
    return user


@app.post("/auth/api-keys")
async def create_api_key(req: APIKeyCreate, user: dict = Depends(require_auth)):
    import secrets
    key_value = "shieldai_live_" + secrets.token_hex(24)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO api_keys (key_value, name, user_id) VALUES (?, ?, ?)",
            (key_value, req.name, user["username"])
        )
        conn.commit()
    return {"status": "ok", "key": key_value, "name": req.name}


@app.get("/auth/api-keys")
async def get_api_keys(user: dict = Depends(require_auth)):
    with get_db() as conn:
        cur = conn.execute(
            "SELECT id, name, key_value, created_at, last_used_at, is_active FROM api_keys ORDER BY created_at DESC"
        )
        keys = []
        for row in cur.fetchall():
            d = dict(row)
            kv = d["key_value"]
            if len(kv) > 16:
                d["key_value"] = kv[:12] + "..." + kv[-4:]
            keys.append(d)
        return keys


@app.delete("/auth/api-keys/{key_id}")
async def revoke_api_key(key_id: int, user: dict = Depends(require_auth)):
    with get_db() as conn:
        conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        conn.commit()
    return {"status": "revoked"}


# ══════════════════════════════════════════════════════════════
#  LOG INGESTION (rate-limited, no auth — uses API key in production)
# ══════════════════════════════════════════════════════════════

@app.post("/ingest")
async def ingest_log(log: TelemetryLog, request: Request, background_tasks: BackgroundTasks):
    # API Key Authentication
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:]
    
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key is missing. Pass X-API-Key header.")

    with get_db() as conn:
        cur = conn.execute("SELECT 1 FROM api_keys WHERE key_value = ? AND is_active = 1", (api_key,))
        if not cur.fetchone():
            raise HTTPException(status_code=401, detail="Invalid API Key")
        conn.execute("UPDATE api_keys SET last_used_at = datetime('now') WHERE key_value = ?", (api_key,))
        conn.commit()

    client_ip = request.client.host if request.client else "unknown"
    device_fp = calculate_fingerprint(log.user_agent, log.device_id, log.headers)

    # Enforce active blocks
    with get_db() as conn:
        cur = conn.execute(
            "SELECT 1 FROM responses WHERE action_type IN ('TEMP_BLOCK', 'PERM_BLOCK') AND status = 'ACTIVE' AND target IN (?, ?)",
            (log.source_ip, device_fp)
        )
        if cur.fetchone():
            raise HTTPException(status_code=403, detail="Blocked due to suspicious activity.")

    # Rate limiting
    if not _rate_limiter.check(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Max 500 requests per minute.",
            headers={"Retry-After": "60"}
        )

    with get_db() as conn:
        conn.execute(
            "INSERT INTO logs (event_type, source_ip, user_id, status, device_id, "
            "user_agent, endpoint, method, device_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (log.event_type, log.source_ip, log.user_id, log.status,
             log.device_id, log.user_agent, log.endpoint, log.method, device_fp)
        )
        conn.commit()

    broadcast_event({
        "type": "new_log",
        "log": {
            "event_type": log.event_type,
            "source_ip": log.source_ip,
            "user_id": log.user_id,
            "status": log.status,
        }
    })

    check_for_abuse(log.source_ip, log.user_id, log.device_id, log.user_agent, log.headers, background_tasks=background_tasks)
    return {"status": "ok"}


# ══════════════════════════════════════════════════════════════
#  ALERTS
# ══════════════════════════════════════════════════════════════

@app.get("/alerts")
async def get_alerts():
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
        return [dict(row) for row in cur.fetchall()]


@app.get("/alerts/{alert_id}/details")
async def get_alert_details(alert_id: int):
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        alert = cur.fetchone()
        if not alert:
            return {"error": "Alert not found"}
        alert = dict(alert)

        cur = conn.execute("SELECT * FROM logs WHERE source_ip = ? ORDER BY timestamp ASC",
                          (alert['attacker_ip'],))
        related_logs = [dict(row) for row in cur.fetchall()]

        cur = conn.execute(
            "SELECT * FROM responses WHERE alert_id = ? OR target = ? ORDER BY timestamp ASC",
            (alert_id, alert['attacker_ip']))
        related_responses = [dict(row) for row in cur.fetchall()]

    enrichment = enrich_ip(alert['attacker_ip'])

    # Parse evidence citations
    citations = []
    try:
        citations = json.loads(alert.get('evidence_citations', '[]'))
    except (json.JSONDecodeError, TypeError):
        pass

    return {
        "alert": alert,
        "related_logs": related_logs,
        "related_responses": related_responses,
        "enrichment": enrichment,
        "evidence_citations": citations,
    }


@app.post("/alerts/{alert_id}/verdict")
async def set_verdict(alert_id: int, req: VerdictRequest):
    with get_db() as conn:
        # Get alert info for feedback
        cur = conn.execute("SELECT attack_type, evidence FROM alerts WHERE id = ?", (alert_id,))
        alert = cur.fetchone()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        conn.execute("UPDATE alerts SET verdict = ? WHERE id = ?", (req.verdict, alert_id))

        # Save feedback for ML learning loop
        conn.execute(
            "INSERT INTO analyst_feedback (alert_id, verdict, notes, attack_type, evidence_snapshot) "
            "VALUES (?, ?, ?, ?, ?)",
            (alert_id, req.verdict, req.notes, alert['attack_type'], alert['evidence'])
        )
        conn.commit()

    return {"status": "ok"}


@app.get("/alerts/{alert_id}/investigate")
async def investigate_alert(alert_id: int):
    with get_db() as conn:
        cur = conn.execute("SELECT attacker_ip FROM alerts WHERE id = ?", (alert_id,))
        alert = cur.fetchone()
        if not alert:
            return {"error": "Alert not found"}

    investigation_data = build_attack_graph(alert["attacker_ip"])
    return investigation_data


# ══════════════════════════════════════════════════════════════
#  INCIDENTS
# ══════════════════════════════════════════════════════════════

@app.get("/incidents")
async def get_incidents():
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM incidents ORDER BY timestamp DESC")
        return [dict(row) for row in cur.fetchall()]


@app.get("/incidents/{incident_id}/details")
async def get_incident_details(incident_id: int):
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        incident = cur.fetchone()
        if not incident:
            return {"error": "Incident not found"}
        incident = dict(incident)

        cur = conn.execute("SELECT * FROM alerts WHERE incident_id = ?", (incident_id,))
        alerts = [dict(row) for row in cur.fetchall()]

        ips = list(set(a["attacker_ip"] for a in alerts if a["attacker_ip"]))
        fps = list(set(a["device_fingerprint"] for a in alerts if a.get("device_fingerprint")))

        related_logs = []
        if ips:
            placeholders = ",".join("?" for _ in ips)
            cur = conn.execute(
                f"SELECT * FROM logs WHERE source_ip IN ({placeholders}) ORDER BY timestamp ASC", ips)
            related_logs.extend([dict(row) for row in cur.fetchall()])
        if fps:
            placeholders = ",".join("?" for _ in fps)
            cur = conn.execute(
                f"SELECT * FROM logs WHERE device_fingerprint IN ({placeholders}) ORDER BY timestamp ASC", fps)
            related_logs.extend([dict(row) for row in cur.fetchall()])

        seen_log_ids = set()
        dedup_logs = []
        for l in related_logs:
            if l["id"] not in seen_log_ids:
                seen_log_ids.add(l["id"])
                dedup_logs.append(l)
        dedup_logs.sort(key=lambda x: x["timestamp"])

        cur = conn.execute("SELECT * FROM responses WHERE incident_id = ? ORDER BY timestamp ASC",
                          (incident_id,))
        responses = [dict(row) for row in cur.fetchall()]

        enrichment = None
        if incident and incident["correlation_key"]:
            cur = conn.execute("SELECT * FROM threat_intel WHERE ip = ?",
                             (incident["correlation_key"],))
            row = cur.fetchone()
            if row:
                enrichment = dict(row)

    return {
        "incident": incident,
        "alerts": alerts,
        "related_logs": dedup_logs,
        "related_responses": responses,
        "enrichment": enrichment,
    }


@app.post("/incidents/{incident_id}/verdict")
async def set_incident_verdict(incident_id: int, req: VerdictRequest):
    with get_db() as conn:
        conn.execute("UPDATE incidents SET status = 'RESOLVED', verdict = ? WHERE id = ?",
                     (req.verdict, incident_id))
        # Get all alerts in this incident
        cur = conn.execute("SELECT id, attack_type, evidence FROM alerts WHERE incident_id = ?",
                          (incident_id,))
        alerts = [dict(r) for r in cur.fetchall()]
        
        for alert in alerts:
            conn.execute("UPDATE alerts SET verdict = ? WHERE id = ?", (req.verdict, alert['id']))
            conn.execute(
                "INSERT INTO analyst_feedback (alert_id, incident_id, verdict, notes, attack_type, evidence_snapshot) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (alert['id'], incident_id, req.verdict, req.notes,
                 alert.get('attack_type'), alert.get('evidence'))
            )
        conn.commit()
    return {"status": "ok"}


# ══════════════════════════════════════════════════════════════
#  APPROVAL QUEUE
# ══════════════════════════════════════════════════════════════

@app.get("/approvals")
async def get_approvals():
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM pending_approvals ORDER BY timestamp DESC")
        return [dict(row) for row in cur.fetchall()]


@app.post("/approvals/{approval_id}/approve")
async def approve_action(approval_id: int, req: ApprovalRequest = None):
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM pending_approvals WHERE id = ? AND status = 'PENDING'",
                          (approval_id,))
        approval = cur.fetchone()
        if not approval:
            raise HTTPException(status_code=404, detail="Pending approval not found")
        approval = dict(approval)

        conn.execute(
            "UPDATE pending_approvals SET status = 'APPROVED', reviewed_by = 'analyst', "
            "reviewed_at = datetime('now') WHERE id = ?",
            (approval_id,)
        )
        conn.commit()

    # Execute the approved action
    evidence = json.loads(approval.get('evidence_snapshot', '{}') or '{}')
    if approval['action_type'] == 'PERM_BLOCK':
        _response_engine.execute_perm_block(
            approval['target'], approval.get('alert_id'), approval.get('incident_id'),
            evidence, approved_by="analyst"
        )
    elif approval['action_type'] == 'LOCK_ACCOUNT':
        _response_engine._save_response(
            "LOCK_ACCOUNT", approval['target'],
            f"Account {approval['target']} locked. Approved by analyst.",
            approval.get('alert_id'), approval.get('incident_id'),
            tier=5, status="ACTIVE", approved_by="analyst", approval_status="APPROVED"
        )
        _response_engine._write_audit(
            "LOCK_ACCOUNT", 5, approval['target'], approval.get('alert_id'),
            approval.get('incident_id'), evidence, "APPROVED", "SUCCESS",
            approved_by="analyst"
        )

    broadcast_event({"type": "approval_processed", "approval_id": approval_id, "status": "APPROVED"})
    return {"status": "approved"}


@app.post("/approvals/{approval_id}/reject")
async def reject_action(approval_id: int, req: ApprovalRequest = None):
    with get_db() as conn:
        conn.execute(
            "UPDATE pending_approvals SET status = 'REJECTED', reviewed_by = 'analyst', "
            "reviewed_at = datetime('now') WHERE id = ?",
            (approval_id,)
        )
        conn.commit()

    # Audit the rejection
    _response_engine._write_audit(
        "REJECTION", 0, "N/A", None, None, None, "REJECTED", "REJECTED",
        approved_by="analyst", notes=f"Approval #{approval_id} rejected"
    )

    broadcast_event({"type": "approval_processed", "approval_id": approval_id, "status": "REJECTED"})
    return {"status": "rejected"}


# ══════════════════════════════════════════════════════════════
#  AUDIT LOG
# ══════════════════════════════════════════════════════════════

@app.get("/audit-log")
async def get_audit_log():
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200")
        return [dict(row) for row in cur.fetchall()]


# ══════════════════════════════════════════════════════════════
#  EMAIL DRAFTS
# ══════════════════════════════════════════════════════════════

@app.get("/email-drafts")
async def get_email_drafts():
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM email_drafts ORDER BY timestamp DESC")
        return [dict(row) for row in cur.fetchall()]


@app.post("/email-drafts/{draft_id}/approve")
async def approve_email(draft_id: int):
    result = _response_engine.send_approved_email(draft_id, approved_by="analyst")
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@app.post("/email-drafts/{draft_id}/reject")
async def reject_email(draft_id: int):
    with get_db() as conn:
        conn.execute("UPDATE email_drafts SET status = 'REJECTED', reviewed_by = 'analyst' WHERE id = ?",
                     (draft_id,))
        conn.commit()
    return {"status": "rejected"}


# ══════════════════════════════════════════════════════════════
#  ACTIVE BLOCKS
# ══════════════════════════════════════════════════════════════

@app.get("/blocks")
async def get_blocks():
    with get_db() as conn:
        cur = conn.execute(
            "SELECT * FROM responses WHERE action_type IN ('TEMP_BLOCK', 'PERM_BLOCK', 'BLOCK_IP', "
            "'RATE_LIMIT', 'CAPTCHA_CHALLENGE') AND status = 'ACTIVE' ORDER BY timestamp DESC")
        return [dict(row) for row in cur.fetchall()]


@app.post("/blocks/{block_id}/unblock")
async def manual_unblock(block_id: int):
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM responses WHERE id = ? AND status = 'ACTIVE'", (block_id,))
        block = cur.fetchone()
        if not block:
            raise HTTPException(status_code=404, detail="Active block not found")
        block = dict(block)
        conn.execute("UPDATE responses SET status = 'MANUALLY_REMOVED' WHERE id = ?", (block_id,))
        conn.commit()

    _response_engine._write_audit(
        "MANUAL_UNBLOCK", 0, block['target'], block.get('alert_id'),
        block.get('incident_id'), None, "APPROVED", "SUCCESS",
        approved_by="analyst", notes="Manually unblocked by analyst"
    )
    return {"status": "unblocked"}


# ══════════════════════════════════════════════════════════════
#  RESPONSES
# ══════════════════════════════════════════════════════════════

@app.get("/responses")
async def get_responses():
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM responses ORDER BY timestamp DESC")
        return [dict(row) for row in cur.fetchall()]


# ══════════════════════════════════════════════════════════════
#  LOGS
# ══════════════════════════════════════════════════════════════

@app.get("/logs")
async def get_logs():
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
        return [dict(row) for row in cur.fetchall()]


# ══════════════════════════════════════════════════════════════
#  PDF REPORTS & DIGESTS
# ══════════════════════════════════════════════════════════════

@app.get("/alerts/{alert_id}/report.pdf")
async def download_report(alert_id: int):
    filepath = generate_pdf_report(alert_id)
    if not filepath:
        return {"error": "Alert not found"}
    return FileResponse(filepath, media_type="application/pdf",
                       filename=f"shieldai_report_{alert_id}.pdf")


@app.get("/digest/{period}")
async def download_digest(period: str):
    if period not in ("week", "month"):
        raise HTTPException(status_code=400, detail="Period must be 'week' or 'month'")
    filepath = generate_digest(period)
    return FileResponse(filepath, media_type="application/pdf",
                       filename=f"shieldai_digest_{period}.pdf")


# ══════════════════════════════════════════════════════════════
#  AI CHAT
# ══════════════════════════════════════════════════════════════

@app.post("/chat")
async def chat_endpoint(req: ChatRequest):
    result = handle_chat(req.query)
    return result


# ══════════════════════════════════════════════════════════════
#  STATS
# ══════════════════════════════════════════════════════════════

@app.get("/stats")
async def get_stats():
    with get_db() as conn:
        alerts = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()['c']
        incidents = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()['c']
        blocks = conn.execute(
            "SELECT COUNT(*) as c FROM responses WHERE action_type IN ('BLOCK_IP', 'TEMP_BLOCK', 'PERM_BLOCK')"
        ).fetchone()['c']
        emails = conn.execute(
            "SELECT COUNT(*) as c FROM responses WHERE action_type IN ('SEND_EMAIL', 'DRAFT_EMAIL')"
        ).fetchone()['c']
        logs = conn.execute("SELECT COUNT(*) as c FROM logs").fetchone()['c']
        pending = conn.execute(
            "SELECT COUNT(*) as c FROM pending_approvals WHERE status = 'PENDING'"
        ).fetchone()['c']
        active_blocks = conn.execute(
            "SELECT COUNT(*) as c FROM responses WHERE status = 'ACTIVE' "
            "AND action_type IN ('TEMP_BLOCK', 'PERM_BLOCK', 'RATE_LIMIT')"
        ).fetchone()['c']
        draft_emails = conn.execute(
            "SELECT COUNT(*) as c FROM email_drafts WHERE status = 'DRAFT'"
        ).fetchone()['c']

        cur = conn.execute("SELECT attack_type, COUNT(*) as count FROM alerts GROUP BY attack_type")
        distribution = {row['attack_type']: row['count'] for row in cur.fetchall()}

    return {
        "total_alerts": alerts,
        "total_incidents": incidents,
        "total_blocked": blocks,
        "total_emails": emails,
        "total_logs": logs,
        "pending_approvals": pending,
        "active_blocks": active_blocks,
        "draft_emails": draft_emails,
        "attack_distribution": distribution,
    }


# ══════════════════════════════════════════════════════════════
#  HEALTH & METRICS
# ══════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    try:
        with get_db() as conn:
            conn.execute("SELECT 1")
        db_status = "ok"
    except Exception:
        db_status = "error"

    return {
        "status": "healthy" if db_status == "ok" else "degraded",
        "database": db_status,
        "websocket_clients": len(connected_clients),
    }


@app.get("/metrics")
async def metrics():
    """Prometheus-compatible metrics endpoint."""
    with get_db() as conn:
        alerts = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()['c']
        incidents = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()['c']
        logs = conn.execute("SELECT COUNT(*) as c FROM logs").fetchone()['c']
        blocks = conn.execute(
            "SELECT COUNT(*) as c FROM responses WHERE status = 'ACTIVE' "
            "AND action_type IN ('TEMP_BLOCK', 'PERM_BLOCK')"
        ).fetchone()['c']
        pending = conn.execute(
            "SELECT COUNT(*) as c FROM pending_approvals WHERE status = 'PENDING'"
        ).fetchone()['c']

    metrics_text = f"""# HELP soc_alerts_total Total number of alerts
# TYPE soc_alerts_total counter
soc_alerts_total {alerts}

# HELP soc_incidents_total Total number of incidents
# TYPE soc_incidents_total counter
soc_incidents_total {incidents}

# HELP soc_logs_total Total number of ingested logs
# TYPE soc_logs_total counter
soc_logs_total {logs}

# HELP soc_active_blocks Current number of active blocks
# TYPE soc_active_blocks gauge
soc_active_blocks {blocks}

# HELP soc_pending_approvals Current number of pending approvals
# TYPE soc_pending_approvals gauge
soc_pending_approvals {pending}

# HELP soc_ws_clients Current number of WebSocket clients
# TYPE soc_ws_clients gauge
soc_ws_clients {len(connected_clients)}
"""
    return JSONResponse(content=metrics_text, media_type="text/plain")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
