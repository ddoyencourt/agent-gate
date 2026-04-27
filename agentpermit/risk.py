from __future__ import annotations

import fnmatch
import shlex
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {"score": self.score, "level": self.level, "reasons": self.reasons}


NETWORK_PATTERNS = ("curl", "wget", "ssh", "scp", "nc", "ncat")
DESTRUCTIVE_PATTERNS = ("rm", "shred", "mkfs*", "dd")
PRIVILEGED_PATTERNS = ("sudo", "su", "chmod 777")
SECRET_PATTERNS = (".env", ".env.*", "**/.env", "**/.env.*", "*secret*", "*token*", "*.pem")


def assess_risk(command: list[str]) -> RiskAssessment:
    """Return a simple explainable risk score for a command."""
    rendered = shlex.join(command)
    executable = command[0] if command else ""
    score = 10
    reasons: list[str] = []

    if _matches_any(executable, NETWORK_PATTERNS):
        score += 45
        reasons.append("network command can exfiltrate data or contact external systems")

    if _matches_any(executable, DESTRUCTIVE_PATTERNS):
        score += 45
        reasons.append("destructive command can delete or overwrite data")

    if _matches_any(rendered, PRIVILEGED_PATTERNS):
        score += 50
        reasons.append("privileged command can change system state broadly")

    if any(_matches_any(token, SECRET_PATTERNS) for token in command):
        score += 35
        reasons.append("secret-like path or token reference may expose credentials")

    score = min(score, 100)
    if score >= 80:
        level = "high"
    elif score >= 50:
        level = "medium"
    else:
        level = "low"

    if not reasons:
        reasons.append("no obvious high-risk pattern detected")

    return RiskAssessment(score=score, level=level, reasons=reasons)


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)
