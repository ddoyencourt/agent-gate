from agentpermit.policy import Policy


def test_default_policy_allows_safe_read_only_commands():
    policy = Policy.default()

    assert policy.decide(["python", "-m", "pytest"]).action == "allow"
    assert policy.decide(["ls", "-la"]).action == "allow"


def test_policy_denies_secret_paths_even_when_command_is_otherwise_safe():
    policy = Policy.default()

    decision = policy.decide(["cat", ".env"])

    assert decision.action == "deny"
    assert ".env" in decision.reason


def test_policy_asks_before_network_or_destructive_commands():
    policy = Policy.default()

    assert policy.decide(["curl", "https://example.com"]).action == "ask"
    assert policy.decide(["rm", "-rf", "dist"]).action == "ask"


def test_policy_can_load_yaml_rules(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
allow:
  commands:
    - "python -m pytest"
ask_before:
  commands:
    - "git push *"
deny:
  paths:
    - "secrets/**"
  commands:
    - "sudo *"
""".strip(),
        encoding="utf-8",
    )

    policy = Policy.from_file(policy_file)

    assert policy.decide(["python", "-m", "pytest"]).action == "allow"
    assert policy.decide(["git", "push", "origin", "main"]).action == "ask"
    assert policy.decide(["cat", "secrets/api-key.txt"]).action == "deny"
    assert policy.decide(["sudo", "apt", "update"]).action == "deny"
