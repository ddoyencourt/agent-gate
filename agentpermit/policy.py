from __future__ import annotations

import fnmatch
import shlex
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agentpermit.decision import Decision

DEFAULT_POLICY_YAML = """
allow:
  commands:
    - "python -m pytest*"
    - "pytest*"
    - "python -c *"
    - "ls*"
    - "pwd"
    - "echo *"
ask_before:
  commands:
    - "curl *"
    - "wget *"
    - "ssh *"
    - "git push *"
    - "rm *"
deny:
  paths:
    - ".env"
    - ".env.*"
    - "**/.env"
    - "**/.env.*"
    - "~/.ssh/**"
  commands:
    - "sudo *"
    - "chmod 777 *"
""".strip() + "\n"


@dataclass(frozen=True)
class PolicyRules:
    commands: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Policy:
    allow: PolicyRules = field(default_factory=PolicyRules)
    ask_before: PolicyRules = field(default_factory=PolicyRules)
    deny: PolicyRules = field(default_factory=PolicyRules)

    @classmethod
    def default(cls) -> Policy:
        return cls.from_dict(yaml.safe_load(DEFAULT_POLICY_YAML))

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> Policy:
        return cls(
            allow=_rules_from(data.get("allow", {})),
            ask_before=_rules_from(data.get("ask_before", {})),
            deny=_rules_from(data.get("deny", {})),
        )

    def decide(self, command: list[str]) -> Decision:
        rendered = shlex.join(command)

        denied_path = _first_path_match(command, self.deny.paths)
        if denied_path:
            return Decision("deny", f"command references denied path pattern: {denied_path}")

        denied_command = _first_match(rendered, self.deny.commands)
        if denied_command:
            return Decision("deny", f"command matches denied pattern: {denied_command}")

        ask_command = _first_match(rendered, self.ask_before.commands)
        if ask_command:
            return Decision("ask", f"command needs approval: {ask_command}")

        allowed_command = _first_match(rendered, self.allow.commands)
        if allowed_command:
            return Decision("allow", f"command matches allowed pattern: {allowed_command}")

        return Decision("ask", "no explicit allow rule matched")


def _rules_from(data: dict | None) -> PolicyRules:
    data = data or {}
    return PolicyRules(
        commands=list(data.get("commands") or []),
        paths=list(data.get("paths") or []),
    )


def _first_match(value: str, patterns: list[str]) -> str | None:
    return next((pattern for pattern in patterns if fnmatch.fnmatchcase(value, pattern)), None)


def _first_path_match(command: list[str], patterns: list[str]) -> str | None:
    candidates = [token for token in command if not token.startswith("-")]
    for candidate in candidates:
        normalized = str(Path(candidate).expanduser()) if candidate.startswith("~") else candidate
        for pattern in patterns:
            expanded = str(Path(pattern).expanduser()) if pattern.startswith("~") else pattern
            if fnmatch.fnmatchcase(normalized, expanded) or fnmatch.fnmatchcase(candidate, pattern):
                return pattern
    return None
