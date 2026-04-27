
from typer.testing import CliRunner

from agentpermit.cli import app

runner = CliRunner()


def test_check_reports_decision_for_command():
    result = runner.invoke(app, ["check", "--", "curl", "https://example.com"])

    assert result.exit_code == 0
    assert "ask" in result.stdout.lower()
    assert "curl https://example.com" in result.stdout


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
