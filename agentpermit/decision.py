from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    """A policy decision for a requested command."""

    action: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"action": self.action, "reason": self.reason}
