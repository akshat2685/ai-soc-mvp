"""EDYSOR GDPR Compliance — Right to Erasure & Data Portability.

Provides:
  - Right to be Forgotten (Article 17): Delete all user data across systems
  - Right to Data Portability (Article 20): Export user data as JSON
  - Audit-logged compliance operations
  - Cross-system data discovery
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("edysor.compliance.gdpr")


class GDPRComplianceManager:
    """Handle GDPR requirements including right to erasure and data portability."""

    def __init__(self, db_path: str = ""):
        self._db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "soc.db"
        )
        self._operation_log: List[Dict[str, Any]] = []

    def find_user_data(self, user_id: str) -> Dict[str, Any]:
        """Discover all data associated with a user across tables."""
        user_data: Dict[str, Any] = {}

        if not os.path.exists(self._db_path):
            return user_data

        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row

        # Search across all tables for user references
        search_config = {
            "users": ("username", user_id),
            "incidents": ("assigned_to", user_id),
            "audit_log": ("user", user_id),
            "approvals": ("requested_by", user_id),
            "playbook_runs": ("triggered_by", user_id),
        }

        existing_tables = set(
            row[0] for row in
            conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        )

        for table, (column, value) in search_config.items():
            if table not in existing_tables:
                continue
            try:
                # Check if column exists
                cursor = conn.execute(f"PRAGMA table_info({table})")
                columns = [row[1] for row in cursor.fetchall()]
                if column in columns:
                    rows = conn.execute(
                        f"SELECT * FROM {table} WHERE {column} = ?",
                        (value,)
                    ).fetchall()
                    user_data[table] = [dict(row) for row in rows]
            except Exception as e:
                logger.warning(f"Error searching {table}: {e}")

        conn.close()

        user_data["_discovery_metadata"] = {
            "user_id": user_id,
            "discovered_at": datetime.utcnow().isoformat(),
            "tables_searched": len(search_config),
            "tables_with_data": sum(1 for v in user_data.values() if isinstance(v, list) and v),
        }

        return user_data

    def delete_user_data(self, user_id: str, requester: str = "system") -> Dict[str, Any]:
        """Permanently delete all user data (GDPR Right to be Forgotten — Article 17).
        
        WARNING: This is irreversible. Audit logging is done BEFORE deletion.
        """
        logger.warning(f"GDPR DELETION requested for user: {user_id} by: {requester}")

        results: Dict[str, Any] = {
            "user_id": user_id,
            "requested_by": requester,
            "requested_at": datetime.utcnow().isoformat(),
            "deletions": {},
        }

        if not os.path.exists(self._db_path):
            results["status"] = "no_database"
            return results

        conn = sqlite3.connect(self._db_path)

        # Deletion targets
        deletion_config = {
            "users": ("username", user_id),
            "incidents": ("assigned_to", user_id),
            "audit_log": ("user", user_id),
            "approvals": ("requested_by", user_id),
            "playbook_runs": ("triggered_by", user_id),
        }

        existing_tables = set(
            row[0] for row in
            conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        )

        total_deleted = 0
        for table, (column, value) in deletion_config.items():
            if table not in existing_tables:
                continue
            try:
                cursor = conn.execute(f"PRAGMA table_info({table})")
                columns = [row[1] for row in cursor.fetchall()]
                if column in columns:
                    # Count before delete
                    count = conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE {column} = ?",
                        (value,)
                    ).fetchone()[0]

                    if count > 0:
                        # For audit_log table, we anonymize instead of delete
                        # (to maintain audit chain integrity)
                        if table == "audit_log":
                            conn.execute(
                                f"UPDATE {table} SET {column} = ? WHERE {column} = ?",
                                ("[REDACTED_GDPR]", value)
                            )
                            results["deletions"][table] = {"action": "anonymized", "rows": count}
                        else:
                            conn.execute(
                                f"DELETE FROM {table} WHERE {column} = ?",
                                (value,)
                            )
                            results["deletions"][table] = {"action": "deleted", "rows": count}
                        total_deleted += count
            except Exception as e:
                results["deletions"][table] = {"action": "error", "error": str(e)}
                logger.error(f"Error deleting from {table}: {e}")

        conn.commit()
        conn.close()

        results["total_affected_rows"] = total_deleted
        results["completed_at"] = datetime.utcnow().isoformat()
        results["status"] = "completed"

        self._operation_log.append(results)
        logger.info(f"GDPR deletion completed for {user_id}: {total_deleted} rows affected")

        return results

    def export_user_data(self, user_id: str) -> Dict[str, Any]:
        """Export all user data as JSON (GDPR Right to Data Portability — Article 20)."""
        logger.info(f"GDPR DATA EXPORT requested for user: {user_id}")

        user_data = self.find_user_data(user_id)

        export_package = {
            "export_metadata": {
                "user_id": user_id,
                "exported_at": datetime.utcnow().isoformat(),
                "format": "JSON",
                "version": "1.0",
                "regulation": "GDPR Article 20 — Right to Data Portability",
            },
            "data": user_data,
        }

        self._operation_log.append({
            "operation": "data_export",
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat(),
            "tables_exported": len([v for v in user_data.values() if isinstance(v, list)]),
        })

        return export_package

    def get_operation_log(self) -> List[Dict[str, Any]]:
        """Get log of all GDPR operations."""
        return self._operation_log


# Global GDPR compliance manager
gdpr_manager = GDPRComplianceManager()
