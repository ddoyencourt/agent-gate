from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentpermit.decision import Decision
from agentpermit.risk import RiskAssessment


class AuditLog:
    """Append-only JSONL audit log for agent/tool actions."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(
        self,
        command: list[str],
        decision: Decision,
        exit_code: int | None = None,
        *,
        risk: RiskAssessment | None = None,
        cwd: str | None = None,
        duration_ms: int | None = None,
        approved: bool = False,
    ) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "command": command,
            "decision": decision.as_dict(),
            "exit_code": exit_code,
            "approved": approved,
            "cwd": cwd,
            "duration_ms": duration_ms,
        }
        if risk is not None:
            entry["risk"] = risk.score
            entry["risk_level"] = risk.level
            entry["risk_reasons"] = risk.reasons
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
