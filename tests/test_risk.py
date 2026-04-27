from agentpermit.risk import assess_risk


def test_risk_scores_safe_commands_low():
    result = assess_risk(["python", "-m", "pytest"])

    assert result.score < 30
    assert result.level == "low"


def test_risk_scores_network_commands_medium():
    result = assess_risk(["curl", "https://example.com"])

    assert 50 <= result.score < 80
    assert result.level == "medium"
    assert any("network" in reason for reason in result.reasons)


def test_risk_scores_destructive_secret_commands_high():
    result = assess_risk(["rm", "-rf", ".env"])

    assert result.score >= 80
    assert result.level == "high"
    assert any("destructive" in reason for reason in result.reasons)
    assert any("secret" in reason for reason in result.reasons)
