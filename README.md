# AgentPermit

AgentPermit is an open-source permission, audit, and safety layer for AI agents.
It intercepts tool calls, explains risks, enforces policies, prevents dangerous actions, and keeps replayable audit logs.

Think `sudo`, but for AI agents.

## MVP features

- YAML policy file for `allow`, `ask_before`, and `deny` rules
- CLI wrapper: `agentpermit run -- <command>`
- Dry policy checks: `agentpermit check -- <command>`
- Machine-readable checks: `agentpermit check --json -- <command>`
- Explainable command risk scoring from 0 to 100
- Optional approval for ask-before commands: `agentpermit run --yes -- <command>`
- Configurable JSONL audit log with command, decision, risk, cwd, duration, approval status, and exit code
- Default safeguards for secrets, network commands, destructive commands, and privileged commands

## Install locally

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Quick start

```bash
agentpermit init
agentpermit check -- curl https://example.com
agentpermit check --json -- curl https://example.com
agentpermit run -- python -m pytest
agentpermit run --yes -- curl https://example.com
agentpermit run --audit-log ./audit.jsonl -- python -m pytest
```

Example policy:

```yaml
allow:
  commands:
    - "python -m pytest*"
    - "npm test"
ask_before:
  commands:
    - "rm *"
    - "curl *"
    - "ssh *"
deny:
  paths:
    - ".env"
    - ".env.*"
    - "~/.ssh/**"
  commands:
    - "sudo *"
    - "chmod 777 *"
```

## Roadmap

- Human approval prompts and policy exceptions
- Agent trace replay
- MCP/tool-call proxy mode
- GitHub, file-system, browser, and shell adapters
- Web dashboard for audit review

## License

MIT
