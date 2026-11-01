"""Logger module for HunterOS.

Structured logging with fields:
- timestamp
- project
- action
- target
- scope_status
- policy_decision
- safe_mode
- result

SECURITY NOTES:
- The 'notes' field accepts arbitrary strings and is written to disk as-is.
- Framework does NOT filter or sanitize notes content. Users must not put
  credentials, tokens, or secrets in notes. This is a documented limitation.
- Log entries are JSONL format; control characters are escaped by json.dumps.
- No injection prevention beyond JSON serialization.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path

# Strip control characters and limit length to prevent log injection
# and excessive log file growth
_LOG_ENTRY_MAX_LENGTH = 4096
_CONTROL_CHAR_RE = re.compile(r'[\x00-\x1f\x7f]')


def _sanitize_log_value(value: str) -> str:
    """Sanitize a log value to prevent log injection.
    
    Strips control characters and truncates to max length.
    Does NOT filter sensitive content — that is the user's responsibility.
    """
    if not isinstance(value, str):
        value = str(value)
    # Strip control characters (newlines, tabs, etc.)
    value = _CONTROL_CHAR_RE.sub('', value)
    # Truncate to prevent excessive log growth
    if len(value) > _LOG_ENTRY_MAX_LENGTH:
        value = value[:_LOG_ENTRY_MAX_LENGTH]
    return value


class Logger:
    """Structured logger for HunterOS."""

    def __init__(self, project_name: str = "unknown", log_path: str = None):
        self._project_name = project_name
        if log_path is None:
            home = os.path.expanduser("~")
            self._log_path = Path(home) / ".hunteros" / "logs"
        else:
            self._log_path = Path(log_path) / f"{project_name}_logs"
        self._log_path.mkdir(parents=True, exist_ok=True)
        self._log_file = self._log_path / f"{self._project_name}.jsonl"

    def log(self, action: str, target: str = "",
            scope_status: str = "",
            policy_decision: str = "",
            safe_mode: bool = True,
            result: str = "",
            notes: str = "") -> dict:
        """Log an action with structured fields.
        
        Security: All string fields are sanitized to strip control
        characters and truncate to max length. This prevents log
        injection and excessive log growth. Sensitive content in
        'notes' is NOT filtered — users must not put credentials
        or tokens in notes (documented limitation).
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "project": _sanitize_log_value(self._project_name),
            "action": _sanitize_log_value(action),
            "target": _sanitize_log_value(target),
            "scope_status": _sanitize_log_value(scope_status),
            "policy_decision": _sanitize_log_value(policy_decision),
            "safe_mode": safe_mode,
            "result": _sanitize_log_value(result),
            "notes": _sanitize_log_value(notes),
        }
        with open(self._log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def scope_check(self, target: str, scope_status: str,
                     policy_decision: str, safe_mode: bool,
                     result: str = "") -> dict:
        """Log a scope check."""
        return self.log(
            action="scope_check",
            target=target,
            scope_status=scope_status,
            policy_decision=policy_decision,
            safe_mode=safe_mode,
            result=result,
        )

    def policy_check(self, target: str, policy_decision: str,
                      safe_mode: bool, result: str = "") -> dict:
        """Log a policy check."""
        return self.log(
            action="policy_check",
            target=target,
            policy_decision=policy_decision,
            safe_mode=safe_mode,
            result=result,
        )

    def project_action(self, action: str, target: str = "",
                        result: str = "", notes: str = "") -> dict:
        """Log a project action."""
        return self.log(
            action=action,
            target=target,
            result=result,
            notes=notes,
        )

    def get_logs(self, limit: int = 50) -> list[dict]:
        """Get recent log entries."""
        if not self._log_file.exists():
            return []
        logs = []
        with open(self._log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    logs.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        return logs[-limit:]

    def __repr__(self) -> str:
        return f"Logger(project={self._project_name})"