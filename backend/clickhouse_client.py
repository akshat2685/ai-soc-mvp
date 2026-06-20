"""ClickHouse OLAP security logs client."""
import os
import socket
import logging
import uuid
try:
    import clickhouse_connect
except ImportError:
    clickhouse_connect = None
from datetime import datetime

logger = logging.getLogger(__name__)

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", 8123))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "default")

_ch_client = None
_ch_enabled = None

def check_clickhouse_status() -> bool:
    global _ch_enabled
    if _ch_enabled is not None:
        return _ch_enabled
    try:
        s = socket.create_connection((CLICKHOUSE_HOST, CLICKHOUSE_PORT), timeout=0.5)
        s.close()
        _ch_enabled = True
    except Exception:
        _ch_enabled = False
        logger.warning(f"ClickHouse not reachable at {CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}. Disabling OLAP ClickHouse backend.")
    return _ch_enabled

def get_clickhouse_client():
    global _ch_client
    if clickhouse_connect is None:
        return None
    if not check_clickhouse_status():
        return None
        
    if _ch_client is not None:
        return _ch_client
    try:
        _ch_client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASSWORD,
            database=CLICKHOUSE_DB
        )
        logger.info("Connected to ClickHouse successfully.")
        return _ch_client
    except Exception as e:
        logger.warning(f"ClickHouse connection failed ({CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}): {e}. OLAP features disabled.")
        return None

def init_clickhouse():
    client = get_clickhouse_client()
    if not client:
        return
    
    try:
        client.command("""
            CREATE TABLE IF NOT EXISTS logs (
                id UUID,
                timestamp DateTime64(3),
                event_type String,
                source_ip String,
                user_id String,
                status String,
                device_id String,
                user_agent String,
                endpoint String,
                method String,
                device_fingerprint String,
                geo_country String,
                geo_asn String,
                tenant_id String DEFAULT 'default'
            ) ENGINE = MergeTree()
            ORDER BY (timestamp, event_type, source_ip)
        """)
        logger.info("ClickHouse logs table initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize ClickHouse tables: {e}")

def insert_logs_batch(logs: list[dict]):
    """Insert a list of dict logs into ClickHouse."""
    client = get_clickhouse_client()
    if not client:
        # ClickHouse fallback: when ClickHouse is down, write to SQLite logs
        from database import get_db
        logger.info("[CLICKHOUSE FALLBACK] Directing log write to local database.")
        try:
            with get_db() as conn:
                for log in logs:
                    conn.execute(
                        "INSERT INTO logs (event_type, source_ip, user_id, status, device_id, "
                        "user_agent, endpoint, method, device_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            log.get('event_type'), log.get('source_ip'), log.get('user_id'), log.get('status'),
                            log.get('device_id'), log.get('user_agent'), log.get('endpoint'), log.get('method'),
                            log.get('device_fingerprint')
                        )
                    )
                conn.commit()
        except Exception as db_err:
            logger.error(f"Fallback database log insert failed: {db_err}")
        return
    
    columns = [
        'id', 'timestamp', 'event_type', 'source_ip', 'user_id', 'status',
        'device_id', 'user_agent', 'endpoint', 'method', 'device_fingerprint',
        'geo_country', 'geo_asn', 'tenant_id'
    ]
    
    data = []
    for log in logs:
        log_id = log.get('id')
        if not log_id:
            log_id = uuid.uuid4()
        elif isinstance(log_id, str):
            log_id = uuid.UUID(log_id)
            
        ts = log.get('timestamp')
        if not ts:
            ts = datetime.utcnow()
        elif isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.utcnow()
                
        row = [
            log_id,
            ts,
            log.get('event_type', 'UNKNOWN'),
            log.get('source_ip', '0.0.0.0'),
            log.get('user_id', 'N/A') or 'N/A',
            log.get('status', 'success') or 'success',
            log.get('device_id', 'N/A') or 'N/A',
            log.get('user_agent', 'N/A') or 'N/A',
            log.get('endpoint', 'N/A') or 'N/A',
            log.get('method', 'N/A') or 'N/A',
            log.get('device_fingerprint', 'N/A') or 'N/A',
            log.get('geo_country', 'N/A') or 'N/A',
            log.get('geo_asn', 'N/A') or 'N/A',
            log.get('tenant_id', 'default') or 'default'
        ]
        data.append(row)
        
    try:
        client.insert('logs', data, column_names=columns)
        logger.info(f"Successfully batch inserted {len(logs)} logs into ClickHouse.")
    except Exception as e:
        logger.error(f"ClickHouse batch insert failed: {e}")

def query_clickhouse(query_str: str, params: dict = None) -> list[dict]:
    """Execute a query against ClickHouse and return a list of dictionaries."""
    client = get_clickhouse_client()
    if not client:
        return []
    try:
        result = client.query(query_str, parameters=params)
        cols = result.column_names
        rows = []
        for row in result.result_rows:
            d = dict(zip(cols, row))
            if 'id' in d and isinstance(d['id'], uuid.UUID):
                d['id'] = str(d['id'])
            if 'timestamp' in d and isinstance(d['timestamp'], datetime):
                d['timestamp'] = d['timestamp'].isoformat()
            rows.append(d)
        return rows
    except Exception as e:
        logger.error(f"ClickHouse query failed: {e}")
        return []
