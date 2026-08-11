from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, Severity


def _scan_time(value: datetime | None) -> datetime:
    return value or datetime.now(timezone.utc)


def _metadata(project_path: str | Path, findings: list[Finding], scanned_at: datetime) -> dict:
    counts = Counter(finding.severity.name for finding in findings)
    return {
        "project_path": str(Path(project_path).expanduser().resolve()),
        "scanned_at": scanned_at.isoformat().replace("+00:00", "Z"),
        "total_risks": len(findings),
        "severity_counts": {
            "HIGH": counts["HIGH"],
            "MEDIUM": counts["MEDIUM"],
            "LOW": counts["LOW"],
        },
    }


def render_markdown(
    project_path: str | Path,
    findings: list[Finding],
    *,
    scanned_at: datetime | None = None,
) -> str:
    timestamp = _scan_time(scanned_at)
    metadata = _metadata(project_path, findings, timestamp)
    counts = metadata["severity_counts"]
    lines = [
        "# Agent Risk Scanner Report",
        "",
        f"- **Project path:** `{metadata['project_path']}`",
        f"- **Scanned at:** {metadata['scanned_at']}",
        f"- **Total risks:** {metadata['total_risks']}",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
        f"| HIGH | {counts['HIGH']} |",
        f"| MEDIUM | {counts['MEDIUM']} |",
        f"| LOW | {counts['LOW']} |",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.extend(["No risks were detected by the enabled rules.", ""])
        return "\n".join(lines)

    for index, finding in enumerate(findings, 1):
        safe_snippet = finding.snippet.replace("`", "\\`")
        lines.extend(
            [
                f"### {index}. [{finding.severity.name}] {finding.rule_id}",
                "",
                f"- **File:** `{finding.file_path}`",
                f"- **Line:** {finding.line_number}",
                f"- **Snippet:** `{safe_snippet}`",
                f"- **Why dangerous:** {finding.explanation}",
                f"- **Suggested fix:** {finding.remediation}",
                "",
            ]
        )
    return "\n".join(lines)


def render_json(
    project_path: str | Path,
    findings: list[Finding],
    *,
    scanned_at: datetime | None = None,
) -> str:
    timestamp = _scan_time(scanned_at)
    payload = _metadata(project_path, findings, timestamp)
    payload["findings"] = [finding.to_dict() for finding in findings]
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"

