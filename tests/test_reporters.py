import json
from datetime import datetime, timezone
from pathlib import Path

from agent_risk_scanner.models import Finding, Severity
from agent_risk_scanner.reporters import render_json, render_markdown


SCAN_TIME = datetime(2026, 8, 11, 3, 4, 5, tzinfo=timezone.utc)


def sample_findings() -> list[Finding]:
    return [
        Finding(
            severity=Severity.HIGH,
            rule_id="EXEC_OS_SYSTEM",
            file_path="agent.py",
            line_number=8,
            snippet="os.system(command)",
            explanation="Shell execution is dangerous.",
            remediation="Use validated argument lists.",
        )
    ]


def test_markdown_report_contains_required_fields(tmp_path: Path):
    report = render_markdown(tmp_path, sample_findings(), scanned_at=SCAN_TIME)

    assert "# Agent Risk Scanner Report" in report
    assert f"`{tmp_path.resolve()}`" in report
    assert "2026-08-11T03:04:05Z" in report
    assert "**Total risks:** 1" in report
    assert "| HIGH | 1 |" in report
    assert "EXEC_OS_SYSTEM" in report
    assert "**Line:** 8" in report
    assert "**Why dangerous:**" in report
    assert "**Suggested fix:**" in report


def test_json_report_is_valid_and_structured(tmp_path: Path):
    report = render_json(tmp_path, sample_findings(), scanned_at=SCAN_TIME)
    payload = json.loads(report)

    assert payload["project_path"] == str(tmp_path.resolve())
    assert payload["total_risks"] == 1
    assert payload["severity_counts"] == {"HIGH": 1, "MEDIUM": 0, "LOW": 0}
    assert payload["findings"][0]["severity"] == "HIGH"
    assert payload["findings"][0]["rule_id"] == "EXEC_OS_SYSTEM"

