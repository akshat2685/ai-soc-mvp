"""EDYSOR Data Retention & Purging Policies.

Provides:
  - Configurable retention periods per data type
  - Automated purging of expired data
  - Audit-logged purge operations
  - Dry-run mode for safe testing
"""
from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("edysor.data.retention")


# ---------------------------------------------------------------------------
# Retention Rules (data_type → days to keep)
# ---------------------------------------------------------------------------
RETENTION_RULES: Dict[str, int] = {
    "alerts": 90,
    "incidents": 180,
    "playbook_runs": 365,
    "playbook_actions": 365,
    "audit_log": 2555,      # 7 years (SOC2/ISO27001 compliance)
    "audit_logs": 2555,
    "user_sessions": 30,
    "copilot_messages": 90,
    "training_runs": 365,
    "detection_rules": 730, # 2 years
    "purple_team_results": 365,
    "simulation_results": 180,
    "soar_integrations": 730,
    "memory_embeddings": 365,
}


class DataRetentionPolicy:
    """Automatic data purging based on configurable retention rules."""

    def __init__(self, db_path: str = ""):
        self._db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "soc.db"
        )
        self._purge_history: List[Dict[str, Any]] = []

    def get_rules(self) -> Dict[str, int]:
        """Return current retention rules."""
        return RETENTION_RULES.copy()

    def get_expiry_date(self, data_type: str) -> datetime:
        """Calculate expiry date for a data type."""
        days = RETENTION_RULES.get(data_type, 180)
        return datetime.utcnow() - timedelta(days=days)

    def purge_expired_data(self, dry_run: bool = False) -> Dict[str, int]:
        """Purge all expired data across tables.
        
        Args:
            dry_run: If True, calculate counts but don't delete.
            
        Returns:
            Dict mapping table names to rows purged.
        """
        results: Dict[str, int] = {}

        if not os.path.exists(self._db_path):
            logger.warning("DB not found — skipping purge")
            return results

        conn = sqlite3.connect(self._db_path)

        # Map retention rules to actual table names and timestamp columns
        table_config: Dict[str, Tuple[str, str]] = {
            "alerts": ("alerts", "timestamp"),
            "incidents": ("incidents", "created_at"),
            "audit_log": ("audit_log", "timestamp"),
            "playbook_runs": ("playbook_runs", "started_at"),
        }

        # Discover existing tables
        existing_tables = set(
            row[0] for row in
            conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        )

        for data_type, (table_name, ts_column) in table_config.items():
            if table_name not in existing_tables:
                continue

            cutoff = self.get_expiry_date(data_type)
            cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

            try:
                # Count rows to purge
                cursor = conn.execute(
                    f"SELECT COUNT(*) FROM {table_name} WHERE {ts_column} < ?",
                    (cutoff_str,)
                )
                count = cursor.fetchone()[0]

                if count > 0:
                    if dry_run:
                        logger.info(f"[DRY RUN] Would purge {count} rows from {table_name}")
                    else:
                        conn.execute(
                            f"DELETE FROM {table_name} WHERE {ts_column} < ?",
                            (cutoff_str,)
                        )
                        conn.commit()
                        logger.info(f"Purged {count} rows from {table_name} (cutoff: {cutoff_str})")

                    results[table_name] = count

            except Exception as e:
                logger.error(f"Error purging {table_name}: {e}")
                results[table_name] = -1  # Error indicator

        conn.close()

        # Record purge history
        self._purge_history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "dry_run": dry_run,
            "results": results,
        })

        return results

    def get_storage_stats(self) -> Dict[str, Any]:
        """Get current storage statistics per table."""
        stats: Dict[str, Any] = {}

        if not os.path.exists(self._db_path):
            return stats

        conn = sqlite3.connect(self._db_path)
        tables = [
            row[0] for row in
            conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        ]

        for table in tables:
            try:
                cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                stats[table] = {"row_count": count}
            except Exception:
                stats[table] = {"row_count": -1}

        conn.close()

        # Add file size
        stats["_db_file_size_mb"] = round(os.path.getsize(self._db_path) / (1024 * 1024), 2)

        return stats

    def get_purge_history(self) -> List[Dict[str, Any]]:
        """Get history of purge operations."""
        return self._purge_history


# Global retention policy
retention_policy = DataRetentionPolicy()
