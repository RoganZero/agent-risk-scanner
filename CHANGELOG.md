# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-11

### Added

- Dependency-free Python CLI entry point: `agent-risk-scan <path>`.
- Markdown reports with project path, UTC scan time, severity totals, source location, redacted snippet, explanation, and remediation.
- JSON reports through `--format json` and file output through `--output`.
- Twenty-three static rules covering secrets, code and shell execution, filesystem access, network behavior, and agent/MCP/Skill boundaries.
- Secret redaction for credential-like report snippets.
- Deterministic finding ordering and deduplication.
- Scanning for common source, configuration, shell, and Markdown files, including relevant dot directories such as `.codex-plugin`.
- Intentionally unsafe example project for demonstrations and smoke tests.
- Pytest coverage for secret detection, dangerous commands, output formats, hidden directories, output exclusion, and redaction.
- GitHub Actions CI across Python 3.10, 3.11, and 3.12 with pytest and Markdown/JSON CLI smoke tests.
- Security policy, contribution guide, rule reference, and threat model.

### Security

- Generated reports redact likely secret values instead of reproducing them verbatim.
- Scanner output paths can be excluded from the scan to prevent a previous report from being rescanned.

