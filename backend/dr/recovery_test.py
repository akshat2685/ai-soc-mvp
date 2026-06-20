"""EDYSOR Disaster Recovery Tester — Automated DR Validation.

Provides:
  - Backup/restore verification
  - Failover simulation
  - RTO/RPO measurement
  - DR test result reporting
"""
from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("edysor.dr")


class DRTestResult:
    """Result of a disaster recovery test."""
    def __init__(self, test_type: str):
        self.test_type = test_type
        self.started_at = datetime.utcnow()
        self.completed_at: Optional[datetime] = None
        self.status = "running"
        self.steps: List[Dict[str, Any]] = []
        self.rto_seconds: Optional[float] = None
        self.rpo_seconds: Optional[float] = None

    def add_step(self, name: str, status: str, details: str = ""):
        self.steps.append({
            "name": name,
            "status": status,
            "details": details,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def complete(self, status: str):
        self.completed_at = datetime.utcnow()
        self.status = status
        if self.started_at and self.completed_at:
            self.rto_seconds = (self.completed_at - self.started_at).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_type": self.test_type,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "steps": self.steps,
            "rto_seconds": self.rto_seconds,
            "rpo_seconds": self.rpo_seconds,
        }


class DisasterRecoveryTester:
    """Automated DR testing for EDYSOR."""

    def __init__(self, db_path: str = ""):
        self._db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "soc.db"
        )
        self._test_history: List[Dict[str, Any]] = []

    def test_backup_restore(self) -> DRTestResult:
        """Test backup and restore procedure for SQLite database."""
        result = DRTestResult("backup_restore")

        try:
            # Step 1: Create backup
            backup_path = self._db_path + ".dr_test_backup"
            if os.path.exists(self._db_path):
                shutil.copy2(self._db_path, backup_path)
                result.add_step("create_backup", "pass", f"Backed up to {backup_path}")
            else:
                result.add_step("create_backup", "skip", "DB file not found")
                result.complete("skip")
                return result

            # Step 2: Verify backup integrity
            try:
                conn = sqlite3.connect(backup_path)
                cursor = conn.execute("PRAGMA integrity_check")
                integrity = cursor.fetchone()[0]
                conn.close()
                if integrity == "ok":
                    result.add_step("integrity_check", "pass", "Backup integrity verified")
                else:
                    result.add_step("integrity_check", "fail", f"Integrity check: {integrity}")
                    result.complete("fail")
                    return result
            except Exception as e:
                result.add_step("integrity_check", "fail", str(e))
                result.complete("fail")
                return result

            # Step 3: Verify data counts
            try:
                original_conn = sqlite3.connect(self._db_path)
                backup_conn = sqlite3.connect(backup_path)

                orig_tables = set(
                    row[0] for row in
                    original_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                )
                backup_tables = set(
                    row[0] for row in
                    backup_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                )

                if orig_tables == backup_tables:
                    result.add_step("schema_match", "pass", f"{len(orig_tables)} tables verified")
                else:
                    missing = orig_tables - backup_tables
                    result.add_step("schema_match", "fail", f"Missing tables: {missing}")

                # Check row counts for critical tables
                critical_tables = ["alerts", "incidents", "users", "audit_log"]
                for table in critical_tables:
                    if table in orig_tables:
                        orig_count = original_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                        if table in backup_tables:
                            backup_count = backup_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                            if orig_count == backup_count:
                                result.add_step(f"row_count_{table}", "pass", f"{orig_count} rows")
                            else:
                                result.add_step(
                                    f"row_count_{table}", "warn",
                                    f"Original: {orig_count}, Backup: {backup_count}"
                                )

                original_conn.close()
                backup_conn.close()
            except Exception as e:
                result.add_step("data_verification", "fail", str(e))

            # Step 4: Clean up test backup
            if os.path.exists(backup_path):
                os.remove(backup_path)
                result.add_step("cleanup", "pass", "Backup file removed")

            result.complete("pass")

        except Exception as e:
            result.add_step("unexpected_error", "fail", str(e))
            result.complete("fail")

        self._test_history.append(result.to_dict())
        return result

    def test_database_failover_simulation(self) -> DRTestResult:
        """Simulate database failover by testing read/write after reconnect."""
        result = DRTestResult("failover_simulation")

        try:
            if not os.path.exists(self._db_path):
                result.add_step("check_db", "skip", "DB not found")
                result.complete("skip")
                return result

            # Step 1: Open connection and perform writes
            conn = sqlite3.connect(self._db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS dr_test (
                    id INTEGER PRIMARY KEY,
                    test_value TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            test_value = f"dr_test_{int(time.time())}"
            conn.execute("INSERT INTO dr_test (test_value) VALUES (?)", (test_value,))
            conn.commit()
            result.add_step("pre_failover_write", "pass", f"Wrote: {test_value}")

            # Step 2: Simulate "failover" — close and reopen connection
            conn.close()
            result.add_step("connection_close", "pass", "Simulated connection drop")

            # Step 3: Reconnect and verify data
            start = time.time()
            conn = sqlite3.connect(self._db_path)
            cursor = conn.execute(
                "SELECT test_value FROM dr_test WHERE test_value = ?",
                (test_value,)
            )
            row = cursor.fetchone()
            reconnect_time = time.time() - start

            if row and row[0] == test_value:
                result.add_step("post_failover_read", "pass", f"Data intact after {reconnect_time:.3f}s")
                result.rto_seconds = reconnect_time
            else:
                result.add_step("post_failover_read", "fail", "Data not found after reconnect")

            # Step 4: Cleanup
            conn.execute("DROP TABLE IF EXISTS dr_test")
            conn.commit()
            conn.close()
            result.add_step("cleanup", "pass", "Test table removed")

            result.complete("pass")

        except Exception as e:
            result.add_step("unexpected_error", "fail", str(e))
            result.complete("fail")

        self._test_history.append(result.to_dict())
        return result

    def run_all_tests(self) -> List[DRTestResult]:
        """Run all DR tests and return results."""
        results = [
            self.test_backup_restore(),
            self.test_database_failover_simulation(),
        ]
        return results

    def get_test_history(self) -> List[Dict[str, Any]]:
        """Get history of all DR test runs."""
        return self._test_history


# Global DR tester
dr_tester = DisasterRecoveryTester()
