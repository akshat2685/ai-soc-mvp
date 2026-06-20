"""EDYSOR Safe Command Executor — SOAR Command Injection Prevention.

Provides:
  - Allowlist-based command execution
  - Argument sanitization against shell metacharacters
  - Execution timeout enforcement
  - Full audit logging of all command executions
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import shlex
import subprocess
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("edysor.security.command_executor")


# ---------------------------------------------------------------------------
# Shell Metacharacter Blocklist
# ---------------------------------------------------------------------------
BLOCKED_CHARS = [";", "|", "&", "$", "`", "\n", "\r", "$(", "${", ">>", "<<"]

# ---------------------------------------------------------------------------
# Allowed Commands (whitelist)
# ---------------------------------------------------------------------------
ALLOWED_COMMANDS: Dict[str, str] = {
    # Network diagnostics
    "nslookup": "nslookup",
    "dig": "dig",
    "whois": "whois",
    "ping": "ping",
    "traceroute": "traceroute",
    "tracert": "tracert",
    "nmap": "nmap",
    # File hash verification
    "sha256sum": "sha256sum",
    "md5sum": "md5sum",
    # Network queries
    "curl": "curl",
}

# Resolve full paths on the current platform
if platform.system() == "Windows":
    _system_root = os.environ.get("SystemRoot", r"C:\Windows")
    ALLOWED_COMMANDS.update({
        "nslookup": os.path.join(_system_root, "System32", "nslookup.exe"),
        "ping": os.path.join(_system_root, "System32", "ping.exe"),
        "tracert": os.path.join(_system_root, "System32", "tracert.exe"),
    })


class CommandExecutionError(Exception):
    """Raised when command execution fails validation or times out."""
    pass


class SafeCommandExecutor:
    """Execute system commands with strict validation and sandboxing."""

    def __init__(self, custom_allowlist: Optional[Dict[str, str]] = None):
        self.allowlist = {**ALLOWED_COMMANDS}
        if custom_allowlist:
            self.allowlist.update(custom_allowlist)
        self._execution_log: List[Dict[str, Any]] = []

    def validate_command(self, command: str, args: List[str]) -> tuple[bool, str]:
        """Validate command against allowlist and check args for injection."""

        # Check allowlist
        if command not in self.allowlist:
            return False, f"Command '{command}' not in allowlist"

        # Check arguments for shell metacharacters
        for i, arg in enumerate(args):
            for blocked in BLOCKED_CHARS:
                if blocked in arg:
                    return False, f"Argument {i} contains blocked character: '{blocked}'"

            # Check for path traversal
            if ".." in arg and ("/" in arg or "\\" in arg):
                return False, f"Argument {i} contains path traversal pattern"

        return True, "Valid"

    def execute_sync(
        self,
        command: str,
        args: List[str],
        timeout: int = 30,
        user_id: str = "system",
    ) -> Dict[str, Any]:
        """Execute command synchronously with validation and timeout."""

        is_valid, reason = self.validate_command(command, args)
        if not is_valid:
            logger.warning(f"Command rejected: {command} {args} — {reason}")
            raise CommandExecutionError(reason)

        executable = self.allowlist[command]
        full_cmd = [executable] + args
        start_time = time.time()

        log_entry = {
            "command": command,
            "args": args,
            "user_id": user_id,
            "started_at": start_time,
            "status": "running",
        }

        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,  # CRITICAL: Never use shell=True
            )

            elapsed = time.time() - start_time
            log_entry.update({
                "status": "success" if result.returncode == 0 else "error",
                "return_code": result.returncode,
                "elapsed_seconds": round(elapsed, 3),
                "stdout_length": len(result.stdout),
                "stderr_length": len(result.stderr),
            })
            self._execution_log.append(log_entry)

            logger.info(f"Command executed: {command} rc={result.returncode} in {elapsed:.2f}s")

            return {
                "command": command,
                "args": args,
                "return_code": result.returncode,
                "stdout": result.stdout[:10000],  # Cap output size
                "stderr": result.stderr[:5000],
                "elapsed_seconds": round(elapsed, 3),
            }

        except subprocess.TimeoutExpired:
            log_entry["status"] = "timeout"
            self._execution_log.append(log_entry)
            raise CommandExecutionError(f"Command '{command}' exceeded {timeout}s timeout")

        except FileNotFoundError:
            log_entry["status"] = "not_found"
            self._execution_log.append(log_entry)
            raise CommandExecutionError(f"Command executable not found: {executable}")

        except Exception as e:
            log_entry["status"] = "error"
            log_entry["error"] = str(e)
            self._execution_log.append(log_entry)
            raise CommandExecutionError(f"Command execution failed: {e}")

    async def execute_async(
        self,
        command: str,
        args: List[str],
        timeout: int = 30,
        user_id: str = "system",
    ) -> Dict[str, Any]:
        """Execute command asynchronously (wraps sync execution)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.execute_sync(command, args, timeout, user_id),
        )

    def get_execution_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent command execution log."""
        return self._execution_log[-limit:]

    def get_allowed_commands(self) -> List[str]:
        """Return list of allowed command names."""
        return list(self.allowlist.keys())


# Global instance
safe_executor = SafeCommandExecutor()
