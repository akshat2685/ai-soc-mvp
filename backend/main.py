from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from models import TelemetryLog
from database import init_db, get_db
from detection import check_for_abuse, calculate_fingerprint
from threat_intel import enrich_ip
from chat import handle_chat
from pdf_report import generate_pdf_report
from agentic_investigation import build_attack_graph
import uvicorn
import json
import asyncio
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="AI SOC Platform API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket connection manager ──
connected_clients: list[WebSocket] = []

@app.on_event("startup")
def on_startup():
    init_db()

# ── WebSocket endpoint ──
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
    message = json.dumps(data)
    disconnected = []
    for ws in connected_clients:
        try:
            asyncio.get_event_loop().create_task(ws.send_text(message))
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        connected_clients.remove(ws)

# ── Log Ingestion ──
@app.post("/ingest")
async def ingest_log(log: TelemetryLog):
    device_fp = calculate_fingerprint(log.user_agent, log.device_id)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO logs (event_type, source_ip, user_id, status, device_id, user_agent, endpoint, method, device_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (log.event_type, log.source_ip, log.user_id, log.status, log.device_id, log.user_agent, log.endpoint, log.method, device_fp)
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

    check_for_abuse(log.source_ip, log.user_id, log.device_id, log.user_agent)
    return {"status": "ok"}

# ── Alerts ──
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

        cur = conn.execute("SELECT * FROM logs WHERE source_ip = ? ORDER BY timestamp ASC", (alert['attacker_ip'],))
        related_logs = [dict(row) for row in cur.fetchall()]

        cur = conn.execute("SELECT * FROM responses WHERE alert_id = ? OR target = ? ORDER BY timestamp ASC", (alert_id, alert['attacker_ip']))
        related_responses = [dict(row) for row in cur.fetchall()]

    # Enrich attacker IP
    enrichment = enrich_ip(alert['attacker_ip'])

    return {
        "alert": alert,
        "related_logs": related_logs,
        "related_responses": related_responses,
        "enrichment": enrichment,
    }

@app.post("/alerts/{alert_id}/verdict")
async def set_verdict(alert_id: int, verdict: str):
    with get_db() as conn:
        conn.execute("UPDATE alerts SET verdict = ? WHERE id = ?", (verdict, alert_id))
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

# ── Incidents ──
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
        fps = list(set(a["device_fingerprint"] for a in alerts if a["device_fingerprint"]))

        related_logs = []
        if ips:
            placeholders = ",".join("?" for _ in ips)
            cur = conn.execute(f"SELECT * FROM logs WHERE source_ip IN ({placeholders}) ORDER BY timestamp ASC", ips)
            related_logs.extend([dict(row) for row in cur.fetchall()])
        if fps:
            placeholders = ",".join("?" for _ in fps)
            cur = conn.execute(f"SELECT * FROM logs WHERE device_fingerprint IN ({placeholders}) ORDER BY timestamp ASC", fps)
            related_logs.extend([dict(row) for row in cur.fetchall()])

        seen_log_ids = set()
        dedup_logs = []
        for l in related_logs:
            if l["id"] not in seen_log_ids:
                seen_log_ids.add(l["id"])
                dedup_logs.append(l)
        dedup_logs.sort(key=lambda x: x["timestamp"])

        cur = conn.execute("SELECT * FROM responses WHERE incident_id = ? ORDER BY timestamp ASC", (incident_id,))
        responses = [dict(row) for row in cur.fetchall()]

        # Enrich correlation key if it is an IP
        enrichment = None
        if incident and incident["correlation_key"]:
            cur = conn.execute("SELECT * FROM threat_intel WHERE ip = ?", (incident["correlation_key"],))
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
async def set_incident_verdict(incident_id: int, verdict: str):
    with get_db() as conn:
        conn.execute("UPDATE incidents SET status = 'RESOLVED', verdict = ? WHERE id = ?", (verdict, incident_id))
        conn.execute("UPDATE alerts SET verdict = ? WHERE incident_id = ?", (verdict, incident_id))
        conn.commit()
    return {"status": "ok"}

# ── PDF Report ──
@app.get("/alerts/{alert_id}/report.pdf")
async def download_report(alert_id: int):
    filepath = generate_pdf_report(alert_id)
    if not filepath:
        return {"error": "Alert not found"}
    return FileResponse(filepath, media_type="application/pdf", filename=f"shieldai_report_{alert_id}.pdf")

# ── AI Chat ──
class ChatRequest(BaseModel):
    query: str

@app.post("/chat")
async def chat_endpoint(req: ChatRequest):
    result = handle_chat(req.query)
    return result

# ── Responses ──
@app.get("/responses")
async def get_responses():
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM responses ORDER BY timestamp DESC")
        return [dict(row) for row in cur.fetchall()]

# ── Logs ──
@app.get("/logs")
async def get_logs():
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
        return [dict(row) for row in cur.fetchall()]

# ── Stats ──
@app.get("/stats")
async def get_stats():
    with get_db() as conn:
        alerts = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()['c']
        incidents = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()['c']
        blocks = conn.execute("SELECT COUNT(*) as c FROM responses WHERE action_type = 'BLOCK_IP'").fetchone()['c']
        emails = conn.execute("SELECT COUNT(*) as c FROM responses WHERE action_type = 'SEND_EMAIL'").fetchone()['c']
        logs = conn.execute("SELECT COUNT(*) as c FROM logs").fetchone()['c']

        cur = conn.execute("SELECT attack_type, COUNT(*) as count FROM alerts GROUP BY attack_type")
        distribution = {row['attack_type']: row['count'] for row in cur.fetchall()}

    return {
        "total_alerts": alerts,
        "total_incidents": incidents,
        "total_blocked": blocks,
        "total_emails": emails,
        "total_logs": logs,
        "attack_distribution": distribution,
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
