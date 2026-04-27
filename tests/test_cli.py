import json

from typer.testing import CliRunner

from agentpermit.cli import app

runner = CliRunner()


def test_check_reports_decision_for_command():
    result = runner.invoke(app, ["check", "--", "curl", "https://example.com"])

    assert result.exit_code == 0
    assert "ask" in result.stdout.lower()
    assert "curl https://example.com" in result.stdout


def test_check_can_emit_json_for_automation():
    result = runner.invoke(app, ["check", "--json", "--", "curl", "https://example.com"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == ["curl", "https://example.com"]
    assert payload["decision"]["action"] == "ask"
    assert payload["risk"] >= 50


def test_init_creates_default_policy(tmp_path):
    result = runner.invoke(app, ["init", "--directory", str(tmp_path)])

    assert result.exit_code == 0
    policy_file = tmp_path / ".agentpermit" / "policy.yaml"
    assert policy_file.exists()
    assert "deny:" in policy_file.read_text(encoding="utf-8")


def test_run_executes_allowed_command_and_logs(tmp_path):
    result = runner.invoke(
        app,
        ["run", "--directory", str(tmp_path), "--", "python", "-c", "print('ok')"],
    )

    assert result.exit_code == 0
    assert "ok" in result.stdout
    log_path = tmp_path / ".agentpermit" / "logs" / "session.jsonl"
    assert log_path.exists()


def test_run_blocks_denied_command(tmp_path):
    result = runner.invoke(app, ["run", "--directory", str(tmp_path), "--", "cat", ".env"])

    assert result.exit_code == 2
    assert "denied" in result.stdout.lower()


def test_run_can_execute_ask_command_when_approved_and_records_metadata(tmp_path):
    policy_path = tmp_path / ".agentpermit" / "policy.yaml"
    policy_path.parent.mkdir(parents=True)
    policy_path.write_text(
        """
allow:
  commands: []
ask_before:
  commands:
    - "echo *"
deny:
  commands: []
  paths: []
""".strip(),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["run", "--directory", str(tmp_path), "--yes", "--", "echo", "approved"],
    )

    assert result.exit_code == 0
    assert "approved" in result.stdout
    log_path = tmp_path / ".agentpermit" / "logs" / "session.jsonl"
    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["approved"] is True
    assert entry["cwd"] == str(tmp_path)
    assert isinstance(entry["duration_ms"], int)
    assert entry["risk"] >= 0


def test_run_can_write_json_audit_to_custom_path(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    result = runner.invoke(
        app,
        [
            "run",
            "--directory",
            str(tmp_path),
            "--audit-log",
            str(audit_path),
            "--",
            "python",
            "-c",
            "print('custom')",
        ],
    )

    assert result.exit_code == 0
    assert audit_path.exists()
    entry = json.loads(audit_path.read_text(encoding="utf-8"))
    assert entry["command"] == ["python", "-c", "print('custom')"]
