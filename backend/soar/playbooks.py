import time
import json
import logging
from database import get_db
from soar.config import init_soar_tables
from soar.integrations import (
    slack, teams, jira, servicenow, virustotal, abuseipdb, misp,
    elastic, splunk, sentinel, crowdstrike, defender, paloalto, fortinet
)

logger = logging.getLogger(__name__)

# Playbook Definitions
PLAYBOOK_DEFINITIONS = {
    "IP block": [
        {"name": "enrich_vt", "integration": "virustotal", "type": "enrich"},
        {"name": "enrich_abuseipdb", "integration": "abuseipdb", "type": "enrich"},
        {"name": "block_paloalto", "integration": "paloalto", "type": "contain", "requires_approval": True},
        {"name": "block_fortinet", "integration": "fortinet", "type": "contain", "requires_approval": True}
    ],
    "User disable": [
        {"name": "disable_account", "integration": "database", "type": "contain", "requires_approval": True}
    ],
    "Host isolate": [
        {"name": "isolate_crowdstrike", "integration": "crowdstrike", "type": "contain", "requires_approval": True},
        {"name": "isolate_defender", "integration": "defender", "type": "contain", "requires_approval": True}
    ],
    "Ticket creation": [
        {"name": "create_jira", "integration": "jira", "type": "ticket"},
        {"name": "create_servicenow", "integration": "servicenow", "type": "ticket"}
    ],
    "IOC enrichment": [
        {"name": "enrich_vt", "integration": "virustotal", "type": "enrich"},
        {"name": "enrich_abuseipdb", "integration": "abuseipdb", "type": "enrich"},
        {"name": "enrich_misp", "integration": "misp", "type": "enrich"}
    ]
}

def trigger_playbook(tenant_id: str, playbook_name: str, target: str, incident_id: int = None) -> int:
    """Start or queue a playbook run."""
    init_soar_tables()
    if playbook_name not in PLAYBOOK_DEFINITIONS:
        raise ValueError(f"Playbook {playbook_name} is not defined.")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO soar_playbook_runs (tenant_id, playbook_name, incident_id, target, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'RUNNING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (tenant_id, playbook_name, incident_id, target)
        )
        conn.commit()
        playbook_run_id = cursor.lastrowid

    # Run playbook execution in background/main loop
    execute_playbook_run(playbook_run_id)
    return playbook_run_id

def execute_playbook_run(playbook_run_id: int):
    """Loop through playbook actions and execute them."""
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM soar_playbook_runs WHERE id = ?", (playbook_run_id,))
        run = cur.fetchone()
        if not run:
            return
        run = dict(run)

    tenant_id = run["tenant_id"]
    playbook_name = run["playbook_name"]
    target = run["target"]
    incident_id = run["incident_id"]

    actions = PLAYBOOK_DEFINITIONS[playbook_name]

    for index, action in enumerate(actions):
        # Check if action run already exists (to handle resumes after approval)
        with get_db() as conn:
            cur = conn.execute(
                "SELECT * FROM soar_action_runs WHERE playbook_run_id = ? AND action_name = ?",
                (playbook_run_id, action["name"])
            )
            action_run = cur.fetchone()

        if action_run:
            action_run = dict(action_run)
            if action_run["status"] == "COMPLETED":
                # Already executed, skip to next
                continue
            elif action_run["status"] == "PENDING_APPROVAL":
                # Stopped here waiting for approval
                return

        # Check if action requires approval
        if action.get("requires_approval", False):
            # Check if this action run was already approved
            was_approved = False
            if action_run:
                action_run = dict(action_run)
                # If there's an approval record that is APPROVED, we can proceed
                with get_db() as conn:
                    cur = conn.execute(
                        "SELECT status FROM soar_approvals WHERE playbook_run_id = ? AND action_name = ? ORDER BY id DESC LIMIT 1",
                        (playbook_run_id, action["name"])
                    )
                    app_row = cur.fetchone()
                    if app_row and app_row[0] == "APPROVED":
                        was_approved = True

            if not was_approved:
                # We need to pause and request approval
                with get_db() as conn:
                    # Create or update action run state
                    if action_run:
                        conn.execute(
                            "UPDATE soar_action_runs SET status = 'PENDING_APPROVAL', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                            (action_run["id"],)
                        )
                    else:
                        conn.execute(
                            """
                            INSERT INTO soar_action_runs (playbook_run_id, action_name, integration_name, status, created_at, updated_at)
                            VALUES (?, ?, ?, 'PENDING_APPROVAL', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            """,
                            (playbook_run_id, action["name"], action["integration"])
                        )
                    # Update playbook run status
                    conn.execute(
                        "UPDATE soar_playbook_runs SET status = 'PENDING_APPROVAL', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (playbook_run_id,)
                    )
                    conn.commit()

                from soar.approvals import request_approval
                request_approval(tenant_id, playbook_run_id, action["name"], target, {"playbook": playbook_name, "incident_id": incident_id})
                return

        # Create action run if not exists
        if not action_run:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO soar_action_runs (playbook_run_id, action_name, integration_name, status, created_at, updated_at)
                    VALUES (?, ?, ?, 'RUNNING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                    (playbook_run_id, action["name"], action["integration"])
                )
                conn.commit()
                action_run_id = cursor.lastrowid
        else:
            action_run_id = action_run["id"]
            with get_db() as conn:
                conn.execute(
                    "UPDATE soar_action_runs SET status = 'RUNNING', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (action_run_id,)
                )
                conn.commit()

        # Run Action with Retry Mechanism
        success, response_data, rollback_data, error_msg = run_action_with_retries(tenant_id, action, target)

        if success:
            with get_db() as conn:
                conn.execute(
                    """
                    UPDATE soar_action_runs
                    SET status = 'COMPLETED', response_data = ?, rollback_data = ?, attempt_count = attempt_count + 1, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (json.dumps(response_data), json.dumps(rollback_data), action_run_id)
                )
                conn.commit()
        else:
            # Action failed after all retries -> Rollback preceding actions!
            with get_db() as conn:
                conn.execute(
                    """
                    UPDATE soar_action_runs
                    SET status = 'FAILED', error_message = ?, attempt_count = attempt_count + 1, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (error_msg, action_run_id)
                )
                conn.execute(
                    "UPDATE soar_playbook_runs SET status = 'ROLLING_BACK', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (playbook_run_id,)
                )
                conn.commit()

            trigger_rollback(playbook_run_id)
            return

    # Playbook completed successfully
    with get_db() as conn:
        conn.execute(
            "UPDATE soar_playbook_runs SET status = 'COMPLETED', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (playbook_run_id,)
        )
        conn.commit()

    # Log to final incident/memory platform
    try:
        from memory_integration import record_outcome
        record_outcome(tenant_id, f"SOAR Playbook {playbook_name} completed for {target}", success=True)
    except Exception:
        pass

def run_action_with_retries(tenant_id: str, action: dict, target: str):
    """Execute action and retry if failed."""
    max_retries = 3
    attempt = 0
    success = False
    response_data = None
    rollback_data = None
    error_msg = ""

    while attempt < max_retries:
        attempt += 1
        try:
            res = call_integration_function(tenant_id, action["integration"], action["name"], target)
            if res.get("status") == "success":
                success = True
                response_data = res
                # Determine rollback data if any
                if action["integration"] in ["paloalto", "fortinet"]:
                    rollback_data = {"ip": target}
                elif action["integration"] == "crowdstrike":
                    rollback_data = {"device_id": target}
                elif action["integration"] == "defender":
                    rollback_data = {"machine_id": target}
                elif action["integration"] == "jira":
                    rollback_data = {"ticket_key": res.get("ticket_key")}
                elif action["integration"] == "servicenow":
                    rollback_data = {"sys_id": res.get("sys_id")}
                elif action["integration"] == "misp":
                    rollback_data = {"misp_id": res.get("misp_id")}
                elif action["integration"] == "database":
                    rollback_data = {"user_id": target}
                break
            else:
                error_msg = res.get("error", "Action failed without exception")
        except Exception as e:
            error_msg = str(e)
        
        if attempt < max_retries:
            time.sleep(1) # Simple loop backoff

    return success, response_data, rollback_data, error_msg

def call_integration_function(tenant_id: str, integration: str, action_name: str, target: str) -> dict:
    """Dynamically route action to correct integration."""
    if integration == "virustotal":
        return virustotal.enrich_ioc(tenant_id, target, "ip")
    elif integration == "abuseipdb":
        return abuseipdb.enrich_ip(tenant_id, target)
    elif integration == "misp":
        if action_name == "enrich_misp":
            return misp.enrich_ioc(tenant_id, target, "ip")
        else:
            return misp.publish_ioc(tenant_id, target, "ip")
    elif integration == "paloalto":
        return paloalto.block_ip(tenant_id, target)
    elif integration == "fortinet":
        return fortinet.block_ip(tenant_id, target)
    elif integration == "crowdstrike":
        return crowdstrike.isolate_host(tenant_id, target)
    elif integration == "defender":
        return defender.isolate_machine(tenant_id, target)
    elif integration == "jira":
        return jira.create_ticket(tenant_id, f"Incident Alert: {target}", f"Auto incident ticket created for target {target}.")
    elif integration == "servicenow":
        return servicenow.create_incident(tenant_id, f"Incident Alert: {target}", f"Auto incident ticket created for target {target}.")
    elif integration == "database":
        # Block user in the local database
        with get_db() as conn:
            conn.execute("UPDATE users SET is_active = 0 WHERE username = ? AND tenant_id = ?", (target, tenant_id))
            conn.commit()
        return {"status": "success", "username": target, "is_active": 0}
    return {"status": "failed", "error": f"Unsupported integration: {integration}"}

def resume_playbook_run(playbook_run_id: int, approved_by: str):
    """Resume playbook execution after approval is granted."""
    with get_db() as conn:
        # Resolve the active PENDING_APPROVAL action
        cur = conn.execute(
            "SELECT * FROM soar_action_runs WHERE playbook_run_id = ? AND status = 'PENDING_APPROVAL'",
            (playbook_run_id,)
        )
        act = cur.fetchone()
        if act:
            act = dict(act)
            # Update action status to running/approved
            conn.execute(
                "UPDATE soar_action_runs SET status = 'APPROVED', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (act["id"],)
            )
            # Update playbook status back to running
            conn.execute(
                "UPDATE soar_playbook_runs SET status = 'RUNNING', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (playbook_run_id,)
            )
            conn.commit()

    execute_playbook_run(playbook_run_id)

def trigger_rollback(playbook_run_id: int):
    """Roll back all completed actions for a playbook run in reverse order."""
    with get_db() as conn:
        cur = conn.execute(
            "SELECT * FROM soar_action_runs WHERE playbook_run_id = ? AND status IN ('COMPLETED', 'APPROVED') ORDER BY id DESC",
            (playbook_run_id,)
        )
        completed_actions = [dict(a) for a in cur.fetchall()]
        
        cur_p = conn.execute("SELECT tenant_id FROM soar_playbook_runs WHERE id = ?", (playbook_run_id,))
        p_row = cur_p.fetchone()
        tenant_id = p_row[0] if p_row else "default"

    rollback_success = True
    rollback_errors = []

    for action_run in completed_actions:
        integration = action_run["integration_name"]
        rollback_data = json.loads(action_run["rollback_data"]) if action_run["rollback_data"] else None
        
        if not rollback_data:
            # Enrichment actions don't have rollback data and don't need reversal
            continue

        try:
            logger.info(f"[SOAR Rollback] Rolling back action {action_run['action_name']} via {integration}")
            res = execute_rollback_action(tenant_id, integration, rollback_data)
            if res.get("status") == "success":
                with get_db() as conn:
                    conn.execute("UPDATE soar_action_runs SET status = 'ROLLED_BACK' WHERE id = ?", (action_run["id"],))
                    conn.commit()
            else:
                rollback_success = False
                err_msg = res.get("error", "Rollback failed")
                rollback_errors.append(f"{integration}: {err_msg}")
        except Exception as e:
            rollback_success = False
            rollback_errors.append(f"{integration}: {str(e)}")

    final_status = "ROLLED_BACK" if rollback_success else "ROLLBACK_FAILED"
    error_summary = "; ".join(rollback_errors) if rollback_errors else None
    
    with get_db() as conn:
        conn.execute(
            "UPDATE soar_playbook_runs SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (final_status, playbook_run_id)
        )
        conn.commit()

    logger.info(f"[SOAR Playbook] Rollback completed with status: {final_status}")

def execute_rollback_action(tenant_id: str, integration: str, rollback_data: dict) -> dict:
    """Execute the specific unblock/uninstall/close action for an integration."""
    if integration == "paloalto":
        return paloalto.unblock_ip(tenant_id, rollback_data["ip"])
    elif integration == "fortinet":
        return fortinet.unblock_ip(tenant_id, rollback_data["ip"])
    elif integration == "crowdstrike":
        return crowdstrike.unisolate_host(tenant_id, rollback_data["device_id"])
    elif integration == "defender":
        return defender.unisolate_machine(tenant_id, rollback_data["machine_id"])
    elif integration == "jira":
        return jira.close_ticket(tenant_id, rollback_data["ticket_key"])
    elif integration == "servicenow":
        return servicenow.close_incident(tenant_id, rollback_data["sys_id"])
    elif integration == "misp":
        return misp.delete_ioc(tenant_id, rollback_data["misp_id"])
    elif integration == "database":
        with get_db() as conn:
            conn.execute("UPDATE users SET is_active = 1 WHERE username = ? AND tenant_id = ?", (rollback_data["user_id"], tenant_id))
            conn.commit()
        return {"status": "success", "username": rollback_data["user_id"], "is_active": 1}
    return {"status": "failed", "error": f"Unsupported rollback for: {integration}"}
