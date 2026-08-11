# agent-risk-scanner

`agent-risk-scanner` is a lightweight, dependency-free Python CLI that statically scans AI agent, MCP server, Codex Skill, plugin, and automation projects for common security risks. It produces review-ready Markdown or machine-readable JSON without executing the target project.

Use it to triage hard-coded secrets, dangerous command execution, broad filesystem access, risky outbound requests, and over-permissive agent/tool boundaries. The rules are transparent heuristics: findings identify code for review, not proven exploits.

## Quick start

Python 3.10 or newer is required. From a source checkout:

```bash
python -m pip install .
agent-risk-scan examples/unsafe-agent-project --output report.md
```

Typical output:

```text
Wrote markdown report to report.md (26 risks).
```

```markdown
# Agent Risk Scanner Report

- **Project path:** `/path/to/examples/unsafe-agent-project`
- **Scanned at:** 2026-08-11T03:04:05Z
- **Total risks:** 26

| Severity | Count |
| --- | ---: |
| HIGH | 21 |
| MEDIUM | 4 |
| LOW | 1 |

### 1. [HIGH] SECRET_API_KEY

- **File:** `.env`
- **Line:** 1
- **Snippet:** `ANTHROPIC_API_KEY=<redacted>`
- **Why dangerous:** A likely API credential is embedded in source or configuration and may be exposed through version control.
- **Suggested fix:** Revoke exposed credentials, remove them from history, and load secrets from an approved secret store or environment variable.
```

The included fixture uses nonfunctional example values. Exact counts can change when rules evolve.

## Where it fits

- MCP server implementations and tool handlers
- AI agents and tool wrappers
- Codex Skill and prompt packages
- Plugin projects
- Local or CI automation scripts

## Usage

Print a Markdown report:

```bash
agent-risk-scan path/to/project
```

Write Markdown to a file:

```bash
agent-risk-scan path/to/project --output report.md
```

Print or write JSON:

```bash
agent-risk-scan path/to/project --format json
agent-risk-scan path/to/project --format json --output report.json
```

The package module is also executable after installation:

```bash
python -m agent_risk_scanner path/to/project
```

The CLI returns `2` when the scan target does not exist and `0` after a completed scan, including when findings exist. v0.1.0 does not provide a CI severity/failure threshold; CI consumers can inspect the JSON result.

## Report contents

Both formats include the resolved project path, UTC scan time, total risk count, `HIGH`/`MEDIUM`/`LOW` totals, and findings. Every finding includes severity, `rule_id`, relative file path, line number, snippet, explanation, and suggested remediation. Likely secret values are redacted in both formats.

Findings are sorted deterministically and deduplicated by rule, file, and line. The selected output file is excluded from the scan so an earlier report is not scanned as project input.

## Implemented coverage

| Area | Implemented checks |
| --- | --- |
| Secrets | Selected OpenAI/Anthropic key assignments, GitHub tokens, webhook URLs, bearer tokens, and credential-like `.env` values |
| Execution | Python `eval`/`exec`, `os.system`, selected subprocess APIs, Node child processes, remote-script shell pipes, and recursive shell deletion |
| Filesystem | Selected recursive/home deletion, sensitive-path reads, caller-controlled writes, and tool-level broad path use |
| Network | Selected user-controlled request URLs, literal external destinations without an evident allowlist, and possible upload/exfiltration calls |
| Agent/MCP/Skill | Tool files with selected shell/file sinks, direct caller-shaped input at command/path/URL sinks, and prompt/Skill files without recognized boundary language |

See [the complete rule reference](docs/rules.md) for all 23 rule IDs, exact severities, detection limits, and remediations. See [the threat model](docs/threat-model.md) for trust boundaries and known gaps.

## Files scanned

The scanner reads common Python, JavaScript/TypeScript, shell, PowerShell, Markdown, JSON, TOML, YAML, environment, and configuration text files. It includes relevant dot directories such as `.codex-plugin` but skips common vendor/generated directories such as `.git`, virtual environments, build output, and `node_modules`. Files larger than 1 MB are skipped.

## Development

Install the editable package and the only development dependency:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

The GitHub Actions workflow tests Python 3.10, 3.11, and 3.12, then runs Markdown and JSON CLI smoke tests against the unsafe example project.

Contribution instructions are in [CONTRIBUTING.md](CONTRIBUTING.md). Security reports should follow [SECURITY.md](SECURITY.md). User-visible changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## Limitations and security statement

This is a static auxiliary scanner. Regex and limited file-level context can produce false positives and false negatives. v0.1.0 does not perform full taint analysis, semantic prompt-injection detection, dependency vulnerability scanning, Git-history scanning, runtime permission evaluation, or sandbox execution.

It does not replace threat modeling, human security review, dependency and secret-history scanning, sandboxing, runtime controls, penetration testing, or incident response. A clean report does not mean a project is secure.

## License

MIT
