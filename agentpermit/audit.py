from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from agentpermit.decision import Decision


class AuditLog:
    """Append-only JSONL audit log for agent/tool actions."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(self, command: list[str], decision: Decision, exit_code: int | None = None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "command": command,
            "decision": decision.as_dict(),
            "exit_code": exit_code,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
