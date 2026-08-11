# Contributing

Thank you for helping improve `agent-risk-scanner`. Contributions should keep the project lightweight, auditable, and useful as a first-pass static review tool.

## Development setup

Python 3.10 or newer is required.

```bash
python -m pip install -e ".[dev]"
python -m pytest
agent-risk-scan examples/unsafe-agent-project --output report.md
```

The runtime package intentionally has no third-party dependencies. Discuss a new runtime dependency before adding it.

## Adding a scanning rule

1. Choose a stable, descriptive uppercase `rule_id`. Use the existing category prefixes: `SECRET_`, `EXEC_`, `SHELL_`, `FS_`, `NET_`, or `AGENT_`.
2. Choose severity based on likely impact in an agent project:
   - `HIGH`: likely credential exposure, arbitrary execution, destructive access, sensitive reads, SSRF, exfiltration, or broad tool authority.
   - `MEDIUM`: a dangerous capability whose exploitability depends on surrounding validation or configuration.
   - `LOW`: a defense-in-depth or documentation gap without a direct exploit demonstrated by the match.
3. For a single-line pattern, add a `RegexRule` through `_rule(...)` in `src/agent_risk_scanner/rules.py`. Restrict `suffixes` when the syntax is language-specific.
4. For a check that needs file-level context, add narrowly scoped logic to `contextual_findings(...)` and register its ID and severity in `CONTEXTUAL_RULE_SEVERITIES`.
5. Provide a concise explanation of why the match matters and a concrete remediation. Do not claim data flow or exploitability that the implementation cannot establish.
6. If a finding may include a credential, route its snippet through `redact_secret_snippet(...)` and add a test proving that the value is absent from output.
7. Add or update `docs/rules.md`. The documentation consistency test requires every implemented ID to be listed.

Prefer focused patterns over broad keywords. Add suffix constraints and negative cases when they materially reduce false positives. Keep file processing deterministic and do not execute the scanned project.

## Tests and fixtures

Add a focused pytest test for each behavior change. A useful rule test normally includes:

- a minimal positive fixture that must match;
- a safe or unrelated form that must not match when false positives are plausible;
- the expected `rule_id`, severity, file path, and line number when relevant;
- a redaction assertion for secret rules.

Use synthetic, nonfunctional credentials and reserved/example domains. The files under `examples/unsafe-agent-project/` are intentionally unsafe demonstrations, not production patterns.

Run before submitting:

```bash
python -m pytest
agent-risk-scan examples/unsafe-agent-project --output report.md
agent-risk-scan examples/unsafe-agent-project --format json --output report.json
```

## Changing report fields

The finding schema lives in `src/agent_risk_scanner/models.py`; shared metadata and Markdown/JSON serialization live in `src/agent_risk_scanner/reporters.py`.

When adding, renaming, or changing a report field:

1. update the `Finding` model or shared metadata builder;
2. update both Markdown and JSON renderers unless the field is explicitly format-specific;
3. update `tests/test_reporters.py` and any CLI tests;
4. update the README example and relevant documentation;
5. describe user-visible changes in `CHANGELOG.md`.

Treat JSON field removal or renaming as a compatibility change. Keep secret redaction consistent across both output formats.

## Pull requests

Keep changes focused. Explain the risk pattern, expected false-positive tradeoffs, test evidence, and documentation updates. Security fixes should follow `SECURITY.md` rather than begin as a public pull request when disclosure would create risk.
