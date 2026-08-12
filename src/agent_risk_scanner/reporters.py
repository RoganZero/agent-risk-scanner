from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, ScanResult


def _scan_time(value: datetime | None) -> datetime:
    return value or datetime.now(timezone.utc)


def _coerce_scan_result(result: ScanResult | list[Finding]) -> ScanResult:
    if isinstance(result, ScanResult):
        return result
    return ScanResult(findings=result, scanned_files=0)


def _metadata(
    project_path: str | Path, scan_result: ScanResult, scanned_at: datetime
) -> dict:
    findings = scan_result.findings
    counts = Counter(finding.severity.name for finding in findings)
    return {
        "project_path": str(Path(project_path).expanduser().resolve()),
        "scanned_at": scanned_at.isoformat().replace("+00:00", "Z"),
        "scan_complete": scan_result.scan_complete,
        "scanned_files": scan_result.scanned_files,
        "skipped_files": len(scan_result.skipped_files),
        "total_risks": len(findings),
        "severity_counts": {
            "HIGH": counts["HIGH"],
            "MEDIUM": counts["MEDIUM"],
            "LOW": counts["LOW"],
        },
    }


def render_markdown(
    project_path: str | Path,
    result: ScanResult | list[Finding],
    *,
    scanned_at: datetime | None = None,
) -> str:
    timestamp = _scan_time(scanned_at)
    scan_result = _coerce_scan_result(result)
    findings = scan_result.findings
    metadata = _metadata(project_path, scan_result, timestamp)
    counts = metadata["severity_counts"]
    lines = [
        "# Agent Risk Scanner Report",
        "",
        f"- **Project path:** `{metadata['project_path']}`",
        f"- **Scanned at:** {metadata['scanned_at']}",
        f"- **Scan complete:** {metadata['scan_complete']}",
        f"- **Scanned files:** {metadata['scanned_files']}",
        f"- **Skipped files:** {metadata['skipped_files']}",
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
    ]

    if scan_result.skipped_files:
        lines.extend(
            [
                "## Skipped Files",
                "",
                "| File | Reason |",
                "| --- | --- |",
            ]
        )
        for skipped_file in scan_result.skipped_files:
            lines.append(f"| `{skipped_file.file_path}` | {skipped_file.reason} |")
        lines.append("")

    lines.extend(["## Findings", ""])

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
    result: ScanResult | list[Finding],
    *,
    scanned_at: datetime | None = None,
) -> str:
    timestamp = _scan_time(scanned_at)
    scan_result = _coerce_scan_result(result)
    payload = _metadata(project_path, scan_result, timestamp)
    payload["skipped_file_details"] = [
        skipped_file.to_dict() for skipped_file in scan_result.skipped_files
    ]
    payload["findings"] = [finding.to_dict() for finding in scan_result.findings]
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
