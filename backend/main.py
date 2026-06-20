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
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends, BackgroundTasks, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from models import TelemetryLog, ChatRequest, LoginRequest, RegisterRequest, VerdictRequest, ApprovalRequest, APIKeyCreate, VulnerabilityRecord, VulnerabilityUpload, DevSecOpsAlert, AssetRecord, AssetInventoryUpload, IDSAlertLog, VirtualPatchRecord, VirtualPatchUpload, KnowledgeUpload, IncidentUpdateRequest
from database import init_db, get_db
from detection import check_for_abuse, calculate_fingerprint, update_entity_baselines
from threat_intel import enrich_ip
from telemetry import init_telemetry, get_tracer
from redis_client import redis_client
from kafka_producer import publish_log
from kafka_consumer import consumer_worker
from datetime import datetime
from chat import handle_chat
from pdf_report import generate_pdf_report
from digest_report import generate_digest
from agentic_investigation import build_attack_graph
from auth import authenticate, register_user, verify_token, get_user_from_token, has_permission
from rate_limiter import IngestRateLimiter
from response import ResponseEngine
import uvicorn
import json
import re
import asyncio
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from health.health_checks import health_checker

load_dotenv()

# ── Rate Limiter ──
_rate_limiter = IngestRateLimiter(max_requests=500, window_seconds=60)
_response_engine = ResponseEngine()


# ── Lifespan ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Global Rate Limiting
    try:
        import redis.asyncio as redis
        from fastapi_limiter import FastAPILimiter
        redis_conn = redis.from_url("redis://localhost:6379", encoding="utf-8", decode_responses=True)
        await FastAPILimiter.init(redis_conn)
        print("[SECURITY] Global Rate Limiter initialized.")
    except Exception as e:
        print(f"[SECURITY] Rate Limiter initialization failed: {e}")

    # Initialize distributed tracing with OTel
    init_telemetry("soc-backend")
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
    except Exception as e:
        print(f"[OTEL] FastAPI instrumentor failed: {e}")
        
    init_db()
    
    # Start Kafka Log Consumer background worker thread
    consumer_worker.start()
    
    # Start baseline background updates (operates on ClickHouse / DB)
    asyncio.create_task(_baseline_updater())
    
    # Mark health check startup complete
    health_checker.mark_startup_complete()
    
    # We no longer need _block_expiry_checker or _rate_limiter_cleanup as Redis handles
    # block expiration TTL and sliding window rates natively without in-process CPU loops!
    yield
    
    # Stop Kafka Consumer worker on shutdown
    consumer_worker.stop()


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

from digital_twin.api import router as digital_twin_router
app.include_router(digital_twin_router)

from api.collaboration import router as collaboration_router
app.include_router(collaboration_router, prefix="/ws/incident")

from xai.api import router as xai_router
app.include_router(xai_router, prefix="/api/v1/xai", tags=["xai"])

from integrations.siem_connectors import router as siem_router
app.include_router(siem_router, prefix="/api/v1/ingest/siem", tags=["siem_ingest"])

from purple_team.api import router as purple_team_router
app.include_router(purple_team_router)

from soar.api import router as soar_router
app.include_router(soar_router)

from training.api import router as training_router
app.include_router(training_router)

from copilot.api import router as copilot_router
app.include_router(copilot_router)

from learning.api import router as learning_router
app.include_router(learning_router)

from telemetry import HAS_PROMETHEUS
if HAS_PROMETHEUS:
    from prometheus_client import make_asgi_app
    app.mount("/metrics", make_asgi_app())

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

from fastapi_limiter.depends import RateLimiter

@app.post("/auth/login", dependencies=[Depends(RateLimiter(times=10, every=60))])
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
    from security.encryption import EncryptionManager
    cipher = EncryptionManager()
    
    key_value = "shieldai_live_" + secrets.token_hex(24)
    encrypted_key = cipher.encrypt(key_value)
    
    with get_db() as conn:
        conn.execute(
            "INSERT INTO api_keys (key_value, name, user_id) VALUES (?, ?, ?)",
            (encrypted_key, req.name, user["username"])
        )
        conn.commit()
    return {"status": "ok", "key": key_value, "name": req.name}


@app.get("/auth/api-keys")
async def get_api_keys(user: dict = Depends(require_auth)):
    from security.encryption import EncryptionManager
    cipher = EncryptionManager()
    
    with get_db() as conn:
        cur = conn.execute(
            "SELECT id, name, key_value, created_at, last_used_at, is_active FROM api_keys ORDER BY created_at DESC"
        )
        keys = []
        for row in cur.fetchall():
            d = dict(row)
            kv_raw = d["key_value"]
            try:
                kv = cipher.decrypt(kv_raw)
            except Exception:
                kv = kv_raw  # Fallback for plain text key
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
async def ingest_log(request: Request, background_tasks: BackgroundTasks):
    client_ip = request.client.host if request.client else "127.0.0.1"

    # 1. Rate Limiting via Redis (extremely fast sliding-window check)
    if not redis_client.check_rate_limit(client_ip, max_requests=500, window_seconds=60):
        await asyncio.sleep(3)  # Tarpit delay to throttle attacker resources
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Max 500 requests per minute.",
            headers={"Retry-After": "60"}
        )

    content_type = request.headers.get('content-type', '')
    if "text/plain" in content_type:
        raw_body = await request.body()
        raw_log = raw_body.decode('utf-8')
        
        # Publish raw unstructured log to Kafka for async parsing, insertion, & analysis
        log_data = {
            "raw_log": raw_log,
            "source_ip": client_ip,
            "timestamp": datetime.utcnow().isoformat()
        }
        publish_log(log_data)
        return {"status": "ok", "message": "Raw log received and queued for ingestion"}

    try:
        data = await request.json()
        from models import TelemetryLog
        log = TelemetryLog(**data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {e}")

    # API Key Authentication
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:]
    
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key is missing. Pass X-API-Key header.")

    from database import verify_api_key
    with get_db() as conn:
        if not verify_api_key(conn, api_key):
            raise HTTPException(status_code=401, detail="Invalid API Key")
        conn.commit()

    device_fp = calculate_fingerprint(log.user_agent, log.device_id, log.headers)

    # 2. Check active blocks in Redis (temp or permanent blocks)
    if redis_client.is_blocked(log.source_ip, device_fp):
        await asyncio.sleep(5)  # Tarpit: waste blocked attacker connection
        raise HTTPException(status_code=403, detail="Blocked due to suspicious activity.")

    # Apply Virtual Patches (WAF Rules)
    with get_db() as conn:
        cur = conn.execute("SELECT rule_name, pattern_regex, action FROM virtual_patches WHERE target_endpoint = '*' OR target_endpoint = ?", (log.endpoint or "",))
        for row in cur.fetchall():
            pattern = row["pattern_regex"]
            payload_str = str(log.headers) if log.headers else ""
            if log.user_agent: payload_str += f" {log.user_agent}"
            
            try:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    if row["action"] == "BLOCK":
                        # Trigger WAF block alert (synchronously or asynchronously)
                        from detection import trigger_incident
                        trigger_incident(
                            title=f"WAF Block: {row['rule_name']}",
                            attack_type="WAF Virtual Patch Match",
                            severity="HIGH",
                            attacker_ip=log.source_ip,
                            events=[log.model_dump()],
                            device_fingerprint=device_fp,
                            confidence_score=95,
                            background_tasks=background_tasks
                        )
                        # Block attacker IP immediately in Redis active defense (1 hour)
                        redis_client.block_target(log.source_ip, expires_in_seconds=3600, is_ip=True)
                        raise HTTPException(status_code=403, detail="Blocked by Web Application Firewall.")
            except re.error:
                pass

    # 3. Publish validated JSON log to Kafka (high-throughput, async OLAP write)
    log_payload = log.model_dump()
    log_payload["device_fingerprint"] = device_fp
    log_payload["timestamp"] = datetime.utcnow().isoformat()
    publish_log(log_payload)

    # Broadcast event is handled by the consumer worker once committed to ClickHouse
    return {"status": "ok"}


# ══════════════════════════════════════════════════════════════
#  ACTIVE DEFENSE: HONEYPOTS
# ══════════════════════════════════════════════════════════════

@app.get("/admin/backup")
@app.get("/api/v1/config.json")
async def honeypot_trigger(request: Request, background_tasks: BackgroundTasks):
    client_ip = request.client.host if request.client else "unknown"
    headers_dict = dict(request.headers)
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Calculate a fingerprint for this attacker
    device_fp = calculate_fingerprint(user_agent, "honeypot-device", headers_dict)
    
    path = request.url.path
    title = f"Honeypot Triggered: Probe on {path}"
    evidence = json.dumps({
        "path": path,
        "method": request.method,
        "client_ip": client_ip,
        "device_fingerprint": device_fp,
        "headers": headers_dict
    })
    
    # 1. Create Alert and auto-block
    with get_db() as conn:
        # Insert Critical Honeypot Alert
        cur = conn.execute(
            "INSERT INTO alerts (title, severity, confidence, confidence_score, attack_type, evidence, attacker_ip, device_fingerprint) "
            "VALUES (?, 'CRITICAL', 'HIGH', 100, 'Honeypot Trigger', ?, ?, ?)",
            (title, evidence, client_ip, device_fp)
        )
        alert_id = cur.lastrowid
        
        # Apply permanent block response to both IP and fingerprint
        for target in (client_ip, device_fp):
            cur_block = conn.execute(
                "SELECT 1 FROM responses WHERE action_type = 'PERM_BLOCK' AND status = 'ACTIVE' AND target = ?",
                (target,)
            )
            if not cur_block.fetchone():
                conn.execute(
                    "INSERT INTO responses (action_type, target, details, alert_id, response_tier, status, approval_status) "
                    "VALUES ('PERM_BLOCK', ?, ?, ?, 5, 'ACTIVE', 'AUTO')",
                    (target, f"Honeypot triggered on {path}", alert_id)
                )
        conn.commit()

    # Broadcast to websocket
    broadcast_event({
        "type": "new_alert",
        "alert": {
            "title": title,
            "severity": "CRITICAL",
            "attacker_ip": client_ip,
            "attack_type": "Honeypot Trigger"
        }
    })
    
    # Tarpit delay: sleep 10s to block/waste attacker's script resource
    await asyncio.sleep(10)
    
    # Return fake 404
    raise HTTPException(status_code=404, detail="Not Found")


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

    # Resolve MITRE Mapping
    from mitre_engine import get_mitre_mapping
    mitre_map = get_mitre_mapping(alert.get('attack_type'))

    return {
        "alert": alert,
        "related_logs": related_logs,
        "related_responses": related_responses,
        "enrichment": enrichment,
        "evidence_citations": citations,
        "mitre_mapping": mitre_map,
    }


@app.get("/mitre/mappings")
async def list_mitre_mappings():
    from mitre_engine import get_all_mitre_mappings
    return get_all_mitre_mappings()


@app.get("/alerts/{alert_id}/mitre")
async def get_alert_mitre(alert_id: int):
    with get_db() as conn:
        cur = conn.execute("SELECT attack_type FROM alerts WHERE id = ?", (alert_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        attack_type = row["attack_type"]
    
    from mitre_engine import get_mitre_mapping
    return get_mitre_mapping(attack_type)


@app.get("/alerts/{alert_id}/investigation")
async def get_alert_investigation(alert_id: int):
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM investigations WHERE alert_id = ?", (alert_id,))
        row = cur.fetchone()
        if row:
            return dict(row)
    
    # If not found, run it on-demand
    from investigation_engine import run_investigation
    result = run_investigation(alert_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@app.post("/alerts/{alert_id}/investigate")
async def trigger_alert_investigation(alert_id: int):
    from investigation_engine import run_investigation
    result = run_investigation(alert_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


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
        conn.execute("UPDATE incidents SET status = 'RESOLVED', verdict = ?, resolved_at = datetime('now') WHERE id = ?",
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
            # Continuous Learning Loop: Ingest feedback into RAG
            try:
                from rag_engine import ingest_analyst_feedback
                ingest_analyst_feedback(alert['id'], alert.get('attack_type', 'UNKNOWN'), req.notes or '', req.verdict)
            except Exception as e:
                print(f"[RAG] Failed to ingest analyst feedback: {e}")
        conn.commit()
    return {"status": "ok"}

@app.put("/api/v1/incidents/{incident_id}")
async def update_incident(incident_id: int, req: IncidentUpdateRequest, user: dict = Depends(require_auth)):
    with get_db() as conn:
        updates = []
        params = []
        if req.status is not None:
            updates.append("status = ?")
            params.append(req.status)
        if req.analyst_notes is not None:
            updates.append("analyst_notes = ?")
            params.append(req.analyst_notes)
            
        if not updates:
            return {"status": "ok", "message": "No updates provided"}
            
        params.append(incident_id)
        query = f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?"
        conn.execute(query, tuple(params))
        conn.commit()
    return {"status": "ok", "message": "Incident updated"}

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

    # Synchronously remove block from Redis active defense
    redis_client.remove_block(block['target'], is_ip=True)

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


@app.get("/api/v1/reports/digest")
async def download_digest(period: str = "week", user: dict = Depends(require_auth)):
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
#  THREAT INTELLIGENCE ENGINE (PHASE 3)
# ══════════════════════════════════════════════════════════════

@app.post("/threat-intel/sync")
async def trigger_threat_intel_sync(background_tasks: BackgroundTasks, user: dict = Depends(require_auth)):
    from threat_intel_engine import sync_cve_feed, sync_cisa_kev
    
    # We run these async tasks in the background so we don't block the API
    async def run_sync():
        await sync_cve_feed()
        await sync_cisa_kev()
        
    background_tasks.add_task(run_sync)
    return {"status": "ok", "message": "Threat Intelligence synchronization started in background"}


@app.get("/threat-intel/cve/{cve_id}")
async def get_cve_intel(cve_id: str, user: dict = Depends(require_auth)):
    from threat_intel_engine import check_cve, check_cve_kev
    
    cve_data = check_cve(cve_id)
    kev_data = check_cve_kev(cve_id)
    
    if not cve_data and not kev_data:
        raise HTTPException(status_code=404, detail="CVE not found in Threat Intel database")
        
    return {
        "cve_id": cve_id,
        "is_kev": kev_data is not None,
        "cve_details": cve_data,
        "kev_details": kev_data
    }


@app.get("/threat-intel/ip/{ip}")
async def get_ip_intel(ip: str, user: dict = Depends(require_auth)):
    from threat_intel import enrich_ip
    result = enrich_ip(ip)
    if not result:
        raise HTTPException(status_code=404, detail="IP Intel not available")
    return result


@app.get("/threat-intel/report.pdf")
async def download_threat_intel_report(user: dict = Depends(require_auth)):
    from threat_intel_pdf import generate_threat_intel_report
    filepath = generate_threat_intel_report()
    if not filepath:
        raise HTTPException(status_code=500, detail="Failed to generate report")
    return FileResponse(filepath, media_type="application/pdf",
                       filename=f"shieldai_threat_intel.pdf")


@app.get("/threat-intel/hash/{hash_value}")
async def get_hash_intel(hash_value: str, user: dict = Depends(require_auth)):
    from threat_intel_engine import check_file_hash
    result = check_file_hash(hash_value)
    if not result:
        raise HTTPException(status_code=404, detail="Hash intel not available or query failed")
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

@app.get("/health/live")
async def health_live():
    return health_checker.liveness()

@app.get("/health/ready")
async def health_ready():
    res = health_checker.readiness()
    if res["status"] == "not_ready":
        raise HTTPException(status_code=503, detail=res)
    return res

@app.get("/health/startup")
async def health_startup():
    res = health_checker.startup()
    if res["status"] == "initializing":
        raise HTTPException(status_code=503, detail=res)
    return res

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


# ══════════════════════════════════════════════════════════════
#  ENTERPRISE INTEGRATIONS: SIEM, VULNERABILITIES, & DEVSECOPS
# ══════════════════════════════════════════════════════════════

@app.get("/siem/export")
async def siem_export(user: dict = Depends(require_auth)):
    """Exports recent alerts in Common Event Format (CEF) for SIEM integration."""
    cef_lines = []
    with get_db() as conn:
        cur = conn.execute("SELECT id, timestamp, title, severity, attack_type, attacker_ip FROM alerts ORDER BY timestamp DESC LIMIT 100")
        for row in cur.fetchall():
            d = dict(row)
            sev_num = 1
            if d["severity"] == "CRITICAL": sev_num = 10
            elif d["severity"] == "HIGH": sev_num = 8
            elif d["severity"] == "MEDIUM": sev_num = 5
            elif d["severity"] == "LOW": sev_num = 3
            
            # Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
            cef = f"CEF:0|ShieldAI|SOC Platform|1.0|{d['attack_type']}|{d['title']}|{sev_num}|rt={d['timestamp']} src={d['attacker_ip'] or '0.0.0.0'} msg=Alert triggered on SOC"
            cef_lines.append(cef)
            
    return JSONResponse(content={"cef": cef_lines}, media_type="application/json")


@app.post("/waf/virtual-patches")
async def add_virtual_patches(payload: VirtualPatchUpload, user: dict = Depends(require_auth)):
    """Deploy Virtual Patches (WAF rules) to block specific payloads at the network layer dynamically."""
    with get_db() as conn:
        for patch in payload.patches:
            conn.execute(
                "INSERT INTO virtual_patches (rule_name, target_endpoint, pattern_regex, action) "
                "VALUES (?, ?, ?, ?)",
                (patch.rule_name, patch.target_endpoint, patch.pattern_regex, patch.action)
            )
        conn.commit()
    return {"status": "ok", "message": f"Successfully deployed {len(payload.patches)} virtual patches."}


@app.get("/waf/virtual-patches")
async def list_virtual_patches(user: dict = Depends(require_auth)):
    """List active Virtual Patches (WAF rules)."""
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM virtual_patches ORDER BY created_at DESC")
        patches = [dict(row) for row in cur.fetchall()]
    return patches


@app.post("/vulnerabilities/upload")
async def upload_vulnerabilities(payload: VulnerabilityUpload, user: dict = Depends(require_auth)):
    """Ingests vulnerability assessment reports from authorized security scanners."""
    with get_db() as conn:
        for r in payload.records:
            conn.execute(
                "INSERT INTO vulnerabilities (ip_address, cve_id, severity, title, description, tool_source) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (r.ip_address, r.cve_id, r.severity, r.title, r.description, r.tool_source)
            )
        conn.commit()
    return {"status": "ok", "message": f"Successfully ingested {len(payload.records)} vulnerability records."}


@app.post("/webhooks/devsecops")
async def devsecops_webhook(alert: DevSecOpsAlert, request: Request):
    """Webhook for ingesting pipeline build alerts (SAST/DAST) from DevSecOps CI/CD runners."""
    # Authenticate via X-API-Key or Bearer Token (using standard key validation)
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:]
            
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key is missing. Pass X-API-Key header.")

    from database import verify_api_key
    with get_db() as conn:
        if not verify_api_key(conn, api_key):
            raise HTTPException(status_code=401, detail="Invalid API Key")
            
        conn.execute(
            "INSERT INTO pipeline_alerts (repo_name, tool_name, cve_id, severity, description, commit_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (alert.repo_name, alert.tool_name, alert.cve_id, alert.severity, alert.description, alert.commit_hash)
        )
        conn.commit()
        
    return {"status": "ok", "message": "Pipeline alert successfully recorded."}


@app.post("/assets/upload")
async def upload_assets(payload: AssetInventoryUpload, user: dict = Depends(require_auth)):
    """Ingests asset inventory mappings linking IP addresses, hostnames, and business criticality."""
    with get_db() as conn:
        for a in payload.assets:
            conn.execute(
                "INSERT INTO assets (ip_address, hostname, owner, os, criticality) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(ip_address) DO UPDATE SET "
                "hostname=excluded.hostname, owner=excluded.owner, os=excluded.os, "
                "criticality=excluded.criticality, last_updated=datetime('now')",
                (a.ip_address, a.hostname, a.owner, a.os, a.criticality)
            )
        conn.commit()
    return {"status": "ok", "message": f"Successfully ingested/updated {len(payload.assets)} assets."}


@app.post("/alerts/ids")
async def ingest_ids_alert(alert: IDSAlertLog, request: Request):
    """Ingests network intrusion detection (IDS/IPS) alerts (e.g. Suricata/Zeek logs) defensively.
    Correlates target asset criticality and vulnerability state to elevate severity and generate remediation."""
    
    # 1. API Key Authentication
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:]
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key is missing")

    from database import verify_api_key
    with get_db() as conn:
        if not verify_api_key(conn, api_key):
            raise HTTPException(status_code=401, detail="Invalid API Key")

    # 2. Risk Correlation & Prioritization
    final_severity = alert.severity.upper()
    asset_criticality = "UNKNOWN"
    matching_vulns = []
    
    with get_db() as conn:
        # Check target asset criticality
        cur_asset = conn.execute("SELECT hostname, criticality FROM assets WHERE ip_address = ?", (alert.target_ip,))
        asset_row = cur_asset.fetchone()
        if asset_row:
            asset_criticality = asset_row["criticality"]
            
        # Check known vulnerabilities for the target asset
        cur_vulns = conn.execute("SELECT cve_id, title FROM vulnerabilities WHERE ip_address = ?", (alert.target_ip,))
        matching_vulns = [dict(row) for row in cur_vulns.fetchall()]

    # Check if any matching vulnerability is in CISA KEV
    from threat_intel_engine import check_cve_kev
    kev_vulnerable = False
    kev_cves = []
    for v in matching_vulns:
        cve_id = v.get("cve_id")
        if cve_id and check_cve_kev(cve_id):
            kev_vulnerable = True
            kev_cves.append(cve_id)

    # Prioritization logic:
    # If target has critical vulnerabilities AND the asset is HIGH criticality, elevate the alert to CRITICAL.
    remediation_notes = "No known matching target vulnerabilities. Monitor normally."
    if matching_vulns:
        vuln_cves = [v["cve_id"] for v in matching_vulns if v["cve_id"]]
        remediation_notes = f"Target host has known vulnerabilities: {', '.join(vuln_cves)}. Apply security patches immediately."
        
        if kev_vulnerable:
            final_severity = "CRITICAL"
            remediation_notes += f" CRITICAL WARNING: Target contains CVE(s) actively exploited in the wild (CISA KEV): {', '.join(kev_cves)}."
        elif asset_criticality == "HIGH":
            final_severity = "CRITICAL"
            remediation_notes += " Priority elevated: Host contains high business criticality data."
        elif final_severity in ("MEDIUM", "LOW"):
            final_severity = "HIGH"

    # 3. Create Alert in SOC database
    title = f"IDS Alert: {alert.signature} targeting {alert.target_ip}"
    evidence = json.dumps({
        "source_ip": alert.source_ip,
        "target_ip": alert.target_ip,
        "protocol": alert.protocol,
        "payload_hex": alert.payload_hex,
        "asset_criticality": asset_criticality,
        "matched_vulnerabilities": matching_vulns,
        "cisa_kev_exploited": kev_cves
    })
    
    with get_db() as conn:
        conn.execute(
            "INSERT INTO alerts (title, severity, confidence, confidence_score, attack_type, evidence, attacker_ip, llm_summary) "
            "VALUES (?, ?, 'HIGH', 90, 'Network Intrusion', ?, ?, ?)",
            (title, final_severity, evidence, alert.source_ip, remediation_notes)
        )
        conn.commit()

    # Broadcast alert to live dashboard via WebSockets
    broadcast_event({
        "type": "new_alert",
        "alert": {
            "title": title,
            "severity": final_severity,
            "attacker_ip": alert.source_ip,
            "attack_type": "Network Intrusion"
        }
    })

    return {
        "status": "ok", 
        "severity_assigned": final_severity, 
        "remediation_recommendation": remediation_notes
    }


@app.post("/knowledge/ingest")
async def ingest_knowledge(payload: KnowledgeUpload, user: dict = Depends(require_auth)):
    """Ingests security playbooks or JSON threat intelligence into the Qdrant RAG vector store."""
    try:
        from rag_engine import ingest_text_document
    except ImportError:
        raise HTTPException(status_code=500, detail="RAG Engine is not installed or configured.")

    total_chunks = 0
    for doc in payload.documents:
        metadata = {"title": doc.title, "source": doc.source}
        chunks = ingest_text_document(doc.content, metadata)
        total_chunks += chunks

    return {"status": "ok", "message": f"Successfully embedded {len(payload.documents)} documents into {total_chunks} vector chunks."}


@app.post("/knowledge/upload-pdf")
async def upload_pdf_playbook(file: UploadFile = File(...), user: dict = Depends(require_auth)):
    """Uploads, parses, and ingests a PDF security playbook into the Qdrant vector store."""
    try:
        from rag_engine import ingest_pdf_bytes
    except ImportError:
        raise HTTPException(status_code=500, detail="RAG Engine is not installed or configured.")

    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")

    try:
        pdf_bytes = await file.read()
        chunks = ingest_pdf_bytes(pdf_bytes, file.filename)
        return {
            "status": "ok",
            "filename": file.filename,
            "chunks_embedded": chunks,
            "message": f"Successfully parsed and embedded {chunks} chunks from PDF playbook."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process PDF: {str(e)}")



# ══════════════════════════════════════════════════════════════
#  THREAT INTELLIGENCE ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.post("/threat-intel/kev/sync")
async def sync_kev(user: dict = Depends(require_auth)):
    """Triggers synchronization of the CISA Known Exploited Vulnerabilities feed."""
    from threat_intel_engine import sync_cisa_kev
    result = await sync_cisa_kev()
    if result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])
    return result


@app.get("/threat-intel/kev/{cve_id}")
async def get_kev_details(cve_id: str, user: dict = Depends(require_auth)):
    """Retrieves threat intelligence metadata for a specific CVE from KEV catalog."""
    from threat_intel_engine import check_cve_kev
    vuln = check_cve_kev(cve_id)
    if not vuln:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in KEV catalog")
    return vuln


@app.get("/threat-intel/ip/{ip}")
async def get_ip_reputation(ip: str, user: dict = Depends(require_auth)):
    """Fetches real-time threat intelligence reputation data for an IP."""
    from threat_intel import enrich_ip
    result = enrich_ip(ip)
    return result

# ══════════════════════════════════════════════════════════════
#  MULTI-AGENT FRAMEWORK (PHASE 5)
# ══════════════════════════════════════════════════════════════
from pydantic import BaseModel

class AgentTaskRequest(BaseModel):
    task: str

@app.post("/api/v1/agents/task")
async def trigger_agent_team(req: AgentTaskRequest, user: dict = Depends(require_auth)):
    """Triggers the Multi-Agent Security Team workflow using LangGraph."""
    try:
        from agents.graph import run_soc_investigation
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Multi-Agent Framework error: {str(e)}")
        
    result = run_soc_investigation(req.task)
    return {
        "status": "ok",
        "messages": result.get("messages", [])
    }

# ══════════════════════════════════════════════════════════════
#  EXECUTIVE SECURITY DASHBOARD (PHASE 7)
# ══════════════════════════════════════════════════════════════
@app.get("/api/v1/executive/metrics")
async def get_executive_metrics(user: dict = Depends(require_auth)):
    with get_db() as conn:
        # Incident metrics
        open_inc = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE status != 'RESOLVED'").fetchone()['c']
        resolved_inc = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE status = 'RESOLVED'").fetchone()['c']
        
        # MTTR (hours)
        mttr_row = conn.execute("SELECT AVG((julianday(resolved_at) - julianday(timestamp)) * 24) as mttr FROM incidents WHERE status = 'RESOLVED' AND resolved_at IS NOT NULL").fetchone()
        mttr = round(mttr_row['mttr'], 1) if mttr_row['mttr'] is not None else 0.0
        
        # MTTD (hours) - Approximated based on alert time vs first log time
        mttd_row = conn.execute("""
            SELECT AVG((julianday(a.timestamp) - julianday(l.min_ts)) * 24) as mttd
            FROM alerts a
            JOIN (SELECT source_ip, MIN(timestamp) as min_ts FROM logs GROUP BY source_ip) l 
              ON a.attacker_ip = l.source_ip
            WHERE a.attacker_ip IS NOT NULL
        """).fetchone()
        mttd = round(mttd_row['mttd'], 1) if mttd_row['mttd'] is not None else 0.0
        
        # Asset Risk Score & Vulns
        high_vulns = conn.execute("SELECT COUNT(*) as c FROM vulnerabilities WHERE severity IN ('HIGH', 'CRITICAL')").fetchone()['c']
        total_assets = conn.execute("SELECT COUNT(*) as c FROM assets").fetchone()['c']
        asset_risk_score = min(100, (high_vulns * 10) + (total_assets * 2))  # simple heuristic
        
        # Security Posture Score
        posture_score = max(0, 100 - (open_inc * 5) - (high_vulns * 3))
        
        # Threat Trends (Last 7 days)
        cur = conn.execute("""
            SELECT date(timestamp) as day, COUNT(*) as c 
            FROM alerts 
            WHERE timestamp >= datetime('now', '-7 days') 
            GROUP BY day ORDER BY day ASC
        """)
        threat_trends = [dict(row) for row in cur.fetchall()]
        
        # Most Targeted IPs
        cur = conn.execute("""
            SELECT attacker_ip, COUNT(*) as c 
            FROM alerts 
            WHERE attacker_ip IS NOT NULL 
            GROUP BY attacker_ip ORDER BY c DESC LIMIT 5
        """)
        top_targets = [dict(row) for row in cur.fetchall()]

    metrics = {
        "open_incidents": open_inc,
        "resolved_incidents": resolved_inc,
        "mttr_hours": mttr,
        "mttd_hours": mttd,
        "posture_score": posture_score,
        "asset_risk_score": asset_risk_score,
        "threat_trends": threat_trends,
        "top_targets": top_targets
    }

    # Generate Executive Summary
    from ai_engine import _call_llm
    prompt = f"""You are the Executive Reporting Agent for EDYSOR SOC.
Generate a concise, 1-paragraph C-suite executive summary based on these current security metrics:
{json.dumps(metrics, indent=2)}

Focus on the posture score, incident resolution times (MTTR), and overall risk. Be professional and authoritative."""
    
    summary = _call_llm(prompt, fallback="Executive Summary: The security posture is stable but requires continuous monitoring.")
    metrics["executive_summary"] = summary

    return metrics

@app.get("/api/v1/incidents/{incident_id}/graph")
async def get_incident_attack_graph(incident_id: int):
    """
    Returns nodes and edges for rendering an interactive Attack Graph.
    Nodes: Attackers, Assets, Vulnerabilities, Alerts
    """
    nodes = []
    edges = []
    
    with get_db() as conn:
        def _dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d
        conn.row_factory = _dict_factory
        
        # 1. Fetch incident
        cur = conn.execute("SELECT id, title FROM incidents WHERE id = ?", (incident_id,))
        inc = cur.fetchone()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        nodes.append({"id": f"inc_{incident_id}", "label": f"Incident {incident_id}\\n{inc['title']}", "group": "incident"})
        
        # 2. Fetch associated alerts
        cur = conn.execute("SELECT id, attack_type, attacker_ip FROM alerts WHERE incident_id = ?", (incident_id,))
        alerts = cur.fetchall()
        
        attacker_ips = set()
        
        for a in alerts:
            alert_id = a['id']
            nodes.append({"id": f"alert_{alert_id}", "label": a['attack_type'], "group": "alert"})
            edges.append({"from": f"alert_{alert_id}", "to": f"inc_{incident_id}", "label": "correlated_into"})
            
            # Attacker IP
            ip = a['attacker_ip']
            if ip:
                if ip not in attacker_ips:
                    nodes.append({"id": f"ip_{ip}", "label": ip, "group": "attacker"})
                    attacker_ips.add(ip)
                edges.append({"from": f"ip_{ip}", "to": f"alert_{alert_id}", "label": "triggered"})
                
        # 3. Fetch investigations for these alerts to get targeted assets and CVEs
        for a in alerts:
            cur = conn.execute("SELECT collected_assets, collected_vulnerabilities FROM investigations WHERE alert_id = ?", (a['id'],))
            inv = cur.fetchone()
            if inv:
                assets = json.loads(inv['collected_assets'] or "[]")
                vulns = json.loads(inv['collected_vulnerabilities'] or "[]")
                
                for asset in assets:
                    asset_ip = asset.get('ip_address')
                    if asset_ip:
                        asset_id = f"asset_{asset_ip}"
                        # avoid duplicates
                        if not any(n['id'] == asset_id for n in nodes):
                            nodes.append({"id": asset_id, "label": f"{asset_ip}\\n{asset.get('hostname','')}", "group": "asset"})
                        
                        edges.append({"from": f"alert_{a['id']}", "to": asset_id, "label": "targets"})
                        
                        # Find matching vulns for this asset
                        for v in vulns:
                            if v.get('ip_address') == asset_ip:
                                cve = v.get('cve_id')
                                vuln_id = f"vuln_{cve}"
                                if not any(n['id'] == vuln_id for n in nodes):
                                    nodes.append({"id": vuln_id, "label": cve, "group": "vulnerability"})
                                edges.append({"from": asset_id, "to": vuln_id, "label": "has_vuln"})

    return {"nodes": nodes, "edges": edges}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
