import json

from agentpermit.audit import AuditLog
from agentpermit.decision import Decision


def test_audit_log_writes_jsonl_entries(tmp_path):
    log_path = tmp_path / "session.jsonl"
    audit = AuditLog(log_path)

    audit.record(
        command=["python", "-m", "pytest"],
        decision=Decision("allow", "safe test command"),
        exit_code=0,
    )

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["command"] == ["python", "-m", "pytest"]
    assert entry["decision"]["action"] == "allow"
    assert entry["decision"]["reason"] == "safe test command"
    assert entry["exit_code"] == 0
    assert "timestamp" in entry
