from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agentpermit.audit import AuditLog
from agentpermit.policy import DEFAULT_POLICY_YAML, Policy

DIRECTORY_OPTION = typer.Option("--directory", "-d", help="Project directory.")

app = typer.Typer(no_args_is_help=True, help="Permission, audit, and safety layer for AI agents.")
console = Console()


def _agentpermit_dir(directory: Path) -> Path:
    return directory / ".agentpermit"


def _policy_path(directory: Path) -> Path:
    return _agentpermit_dir(directory) / "policy.yaml"


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
) -> None:
    """Print the policy decision for a command without executing it."""
    command = list(ctx.args)
    if not command:
        raise typer.BadParameter("missing command after --")
    decision = _load_policy(directory).decide(command)
    console.print(f"{decision.action.upper()}: {' '.join(command)}")
    console.print(decision.reason)


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(
    ctx: typer.Context,
    directory: Annotated[Path, DIRECTORY_OPTION] = Path("."),
) -> None:
    """Apply policy, run an allowed command, and write an audit entry."""
    command = list(ctx.args)
    if not command:
        raise typer.BadParameter("missing command after --")

    policy = _load_policy(directory)
    decision = policy.decide(command)
    log = AuditLog(_agentpermit_dir(directory) / "logs" / "session.jsonl")

    if decision.action == "deny":
        log.record(command, decision, exit_code=2)
        console.print(f"DENIED: {' '.join(command)}")
        console.print(decision.reason)
        raise typer.Exit(2)

    if decision.action == "ask":
        log.record(command, decision, exit_code=3)
        console.print(f"APPROVAL REQUIRED: {' '.join(command)}")
        console.print(decision.reason)
        raise typer.Exit(3)

    completed = subprocess.run(command, cwd=directory, text=True, capture_output=True, check=False)
    if completed.stdout:
        console.print(completed.stdout, end="")
    if completed.stderr:
        console.print(completed.stderr, end="", style="red")
    log.record(command, decision, completed.returncode)
    raise typer.Exit(completed.returncode)
