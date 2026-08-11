# Security Policy

## Supported versions

Security fixes are currently made on the latest `0.1.x` release line and the default branch.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier versions | No |

## Security scope

`agent-risk-scanner` is a lightweight static scanner. Its current rules inspect supported text files for recognizable patterns and limited file-level context related to:

- hard-coded API keys, GitHub tokens, webhook URLs, bearer tokens, and credential-like `.env` values;
- Python, Node.js, and shell execution primitives;
- recursive deletion, sensitive-file reads, and caller-controlled write paths;
- user-controlled URLs, external requests without an evident allowlist, and possible outbound data transmission;
- agent or MCP tools with shell/file authority, direct user input into privileged sinks, and prompt/Skill files without explicit security-boundary language.

The scanner does not execute target code. Secret-like snippets are redacted in Markdown and JSON output. See `docs/rules.md` for the exact implemented rules and `docs/threat-model.md` for assumptions and gaps.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting flow from the repository's **Security** tab when it is available. Include:

- the affected version or commit;
- a minimal reproduction;
- expected and actual behavior;
- security impact and suggested mitigation, if known.

Do not include real credentials, private source code, or personal data. Use synthetic fixtures and redact sensitive paths and tokens.

If private vulnerability reporting is not enabled, open a minimal public issue asking the maintainers for a private reporting channel. Do not publish exploit details or sensitive evidence in that issue. Maintainers should acknowledge a report, reproduce it, assess severity, and coordinate a fix and disclosure before public discussion.

False negatives that allow a dangerous pattern to evade an advertised rule, secret-redaction failures, unsafe path handling in the scanner itself, and report-generation injection issues are examples of relevant security reports. A request for a new rule outside the documented scope is normally a feature request rather than a vulnerability.

## Agent, MCP, and Skill risk model

Agent-oriented software combines untrusted or model-generated text with tools that may hold host, network, or credential authority. The primary trust boundary is the transition from prompt or user-controlled data into a tool call. Relevant failure modes include command injection, path traversal, sensitive-file access, server-side request forgery, data exfiltration, excessive tool permissions, and instructions that omit permission or validation boundaries.

Static source patterns cannot establish the full runtime data flow, deployment sandbox, user-consent model, tool policy, or effective cloud permissions. Reviewers should therefore validate tool schemas, least privilege, isolation, destination allowlists, filesystem roots, secret handling, logging, dependency provenance, and human approval gates in the deployed system.

## Security-review limitation

This tool can produce false positives and false negatives. It does not replace human security review, threat modeling, dependency or version-control history scanning, runtime monitoring, sandboxing, penetration testing, or incident response.

