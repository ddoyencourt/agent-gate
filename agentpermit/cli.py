from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agentpermit.audit import AuditLog
from agentpermit.policy import DEFAULT_POLICY_YAML, Policy
from agentpermit.risk import assess_risk

DIRECTORY_OPTION = typer.Option("--directory", "-d", help="Project directory.")

app = typer.Typer(no_args_is_help=True, help="Permission, audit, and safety layer for AI agents.")
console = Console()


def _agentpermit_dir(directory: Path) -> Path:
    return directory / ".agentpermit"


def _policy_path(directory: Path) -> Path:
    return _agentpermit_dir(directory) / "policy.yaml"


def _default_audit_path(directory: Path) -> Path:
    return _agentpermit_dir(directory) / "logs" / "session.jsonl"


def _load_policy(directory: Path) -> Policy:
    path = _policy_path(directory)
    if path.exists():
        return Policy.from_file(path)
    return Policy.default()


@app.command()
def init(
    directory: Annotated[Path, DIRECTORY_OPTION] = Path("."),
) -> None:
    """Create a default .agentpermit/policy.yaml file."""
    policy_path = _policy_path(directory)
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    if not policy_path.exists():
        policy_path.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")
        console.print(f"Created [bold]{policy_path}[/bold]")
    else:
        console.print(f"Policy already exists: [bold]{policy_path}[/bold]")


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def check(
    ctx: typer.Context,
    directory: Annotated[Path, DIRECTORY_OPTION] = Path("."),
    as_json: Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON.")] = False,
) -> None:
    """Print the policy decision and risk assessment for a command without executing it."""
    command = list(ctx.args)
    if not command:
        raise typer.BadParameter("missing command after --")
    decision = _load_policy(directory).decide(command)
    risk = assess_risk(command)
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "command": command,
                    "decision": decision.as_dict(),
                    "risk": risk.score,
                    "risk_level": risk.level,
                    "risk_reasons": risk.reasons,
                },
                sort_keys=True,
            )
        )
        return
    console.print(f"{decision.action.upper()}: {' '.join(command)}")
    console.print(decision.reason)
    console.print(f"Risk: {risk.level} ({risk.score}/100)")
    for reason in risk.reasons:
        console.print(f"- {reason}")


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(
    ctx: typer.Context,
    directory: Annotated[Path, DIRECTORY_OPTION] = Path("."),
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Approve ask-before commands.")] = False,
    audit_log: Annotated[
        Path | None,
        typer.Option("--audit-log", help="Write JSONL audit entries to this path."),
    ] = None,
) -> None:
    """Apply policy, run approved commands, and write an audit entry."""
    command = list(ctx.args)
    if not command:
        raise typer.BadParameter("missing command after --")

    policy = _load_policy(directory)
    decision = policy.decide(command)
    risk = assess_risk(command)
    log = AuditLog(audit_log or _default_audit_path(directory))
    cwd = str(directory)

    if decision.action == "deny":
        log.record(command, decision, exit_code=2, risk=risk, cwd=cwd)
        console.print(f"DENIED: {' '.join(command)}")
        console.print(decision.reason)
        raise typer.Exit(2)

    approved = decision.action == "ask" and yes
    if decision.action == "ask" and not approved:
        log.record(command, decision, exit_code=3, risk=risk, cwd=cwd)
        console.print(f"APPROVAL REQUIRED: {' '.join(command)}")
        console.print(decision.reason)
        console.print("Re-run with --yes to approve this command.")
        raise typer.Exit(3)

    started = time.monotonic()
    completed = subprocess.run(command, cwd=directory, text=True, capture_output=True, check=False)
    duration_ms = round((time.monotonic() - started) * 1000)
    if completed.stdout:
        console.print(completed.stdout, end="")
    if completed.stderr:
        console.print(completed.stderr, end="", style="red")
    log.record(
        command,
        decision,
        completed.returncode,
        risk=risk,
        cwd=cwd,
        duration_ms=duration_ms,
        approved=approved,
    )
    raise typer.Exit(completed.returncode)
